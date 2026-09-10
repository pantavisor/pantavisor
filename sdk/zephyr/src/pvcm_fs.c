/*
 * PVCM Remote Filesystem Driver
 *
 * Implements Zephyr's fs_file_system_t backed by pvcm-run.
 * Each VFS call is an RPC: send FS_REQ, block for FS_RESP+DATA.
 * Standard fs_open/fs_read/fs_write/fs_readdir all work.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/fs/fs.h>
#include <zephyr/fs/fs_sys.h>
#include <pantavisor/pvcm.h>
#include <pantavisor/pvcm_protocol.h>
#include <pantavisor/pvcm_transport.h>
#include <pantavisor/pvcm_fs.h>

#include <string.h>

LOG_MODULE_REGISTER(pvcm_fs, CONFIG_LOG_DEFAULT_LEVEL);

/* ---- RPC state ---- */

static K_SEM_DEFINE(fs_resp_sem, 0, 1);

static struct {
	uint8_t req_id;
	bool active;
	/* response fields */
	int32_t result;
	uint8_t fh;
	uint32_t data_expected;
	char *data;            /* k_malloc'd for read/stat/readdir */
	size_t data_len;
} fs_pending;

static uint8_t next_fs_req_id = 1;

/* ---- Send helpers ---- */

static void send_fs_data(const struct pvcm_transport *t, uint8_t req_id,
			 const char *data, size_t len)
{
	size_t off = 0;
	while (off < len) {
		pvcm_fs_data_t frame = {
			.op = PVCM_OP_FS_DATA,
			.req_id = req_id,
		};
		size_t chunk = len - off;
		if (chunk > PVCM_MAX_CHUNK_SIZE)
			chunk = PVCM_MAX_CHUNK_SIZE;
		frame.len = (uint16_t)chunk;
		memcpy(frame.data, data + off, chunk);
		t->send_frame(&frame, 4 + chunk);
		off += chunk;
	}
}

static void send_fs_end(const struct pvcm_transport *t, uint8_t req_id)
{
	pvcm_fs_end_t end = {
		.op = PVCM_OP_FS_END,
		.req_id = req_id,
	};
	t->send_frame(&end, sizeof(end) - sizeof(uint32_t));
}

/*
 * Send an FS_REQ and wait for response.
 * path and write_data are sent as FS_DATA frames after the request.
 * For read operations, response data is k_malloc'd into fs_pending.data.
 * Returns the result from FS_RESP, or -ETIMEDOUT.
 */
static int fs_rpc(uint8_t fs_op, uint8_t fh,
		  uint32_t arg1, uint32_t arg2,
		  const char *path, size_t path_len,
		  const void *write_data, size_t write_len,
		  void *read_buf, size_t read_buf_size)
{
	const struct pvcm_transport *t = pvcm_transport_get();
	if (!t) {
		printk("pvcmfs: fs_rpc: no transport!\n");
		return -ENODEV;
	}

	uint8_t rid = next_fs_req_id++;
	if (next_fs_req_id == 0)
		next_fs_req_id = 1;

	/* setup pending */
	k_free(fs_pending.data);
	fs_pending.req_id = rid;
	fs_pending.active = true;
	fs_pending.result = -EIO;
	fs_pending.fh = 0;
	fs_pending.data_expected = 0;
	fs_pending.data = NULL;
	fs_pending.data_len = 0;
	k_sem_reset(&fs_resp_sem);

	/* send request */
	pvcm_fs_req_t req = {
		.op = PVCM_OP_FS_REQ,
		.req_id = rid,
		.fs_op = fs_op,
		.fh = fh,
		.arg1 = arg1,
		.arg2 = arg2,
		.path_len = (uint16_t)path_len,
		.data_len = (uint32_t)write_len,
	};
	t->send_frame(&req, sizeof(req) - sizeof(uint32_t));

	/* send path + write data as FS_DATA frames */
	if (path_len > 0)
		send_fs_data(t, rid, path, path_len);
	if (write_data && write_len > 0)
		send_fs_data(t, rid, write_data, write_len);

	/* send FS_END */
	send_fs_end(t, rid);

	/* wait for response */
	int ret = k_sem_take(&fs_resp_sem, K_SECONDS(10));
	fs_pending.active = false;

	if (ret != 0) {
		LOG_ERR("FS RPC timeout: op=%d", fs_op);
		k_free(fs_pending.data);
		fs_pending.data = NULL;
		return -ETIMEDOUT;
	}

	/* copy read data to caller's buffer if provided */
	if (read_buf && fs_pending.data && fs_pending.data_len > 0) {
		size_t n = fs_pending.data_len < read_buf_size
			   ? fs_pending.data_len : read_buf_size;
		memcpy(read_buf, fs_pending.data, n);
	}

	int result = fs_pending.result;
	/* caller is responsible for fs_pending.data if they need it */
	return result;
}

/* Convenience — discard response data after RPC */
static void fs_rpc_cleanup(void)
{
	k_free(fs_pending.data);
	fs_pending.data = NULL;
}

/* ---- Response handlers (called from server thread) ---- */

void pvcm_fs_on_resp(const uint8_t *buf, int len)
{
	const pvcm_fs_resp_t *resp = (const pvcm_fs_resp_t *)buf;

	if (!fs_pending.active || resp->req_id != fs_pending.req_id)
		return;

	fs_pending.result = resp->result;
	fs_pending.fh = resp->fh;
	fs_pending.data_expected = resp->data_len;

	if (resp->data_len > 0) {
		fs_pending.data = k_malloc(resp->data_len + 1);
		if (fs_pending.data)
			fs_pending.data[0] = '\0';
		fs_pending.data_len = 0;
	} else {
		/* no data — complete immediately */
		k_sem_give(&fs_resp_sem);
	}
}

void pvcm_fs_on_data(const uint8_t *buf, int len)
{
	if (len < 4)
		return;
	const pvcm_fs_data_t *d = (const pvcm_fs_data_t *)buf;

	if (!fs_pending.active || d->req_id != fs_pending.req_id)
		return;
	if (!fs_pending.data)
		return;

	size_t chunk = d->len;
	if (fs_pending.data_len + chunk > fs_pending.data_expected)
		chunk = fs_pending.data_expected - fs_pending.data_len;

	memcpy(fs_pending.data + fs_pending.data_len, d->data, chunk);
	fs_pending.data_len += chunk;
}

void pvcm_fs_on_end(const uint8_t *buf, int len)
{
	if (len < 2)
		return;
	uint8_t req_id = buf[1];

	if (!fs_pending.active || req_id != fs_pending.req_id)
		return;

	if (fs_pending.data)
		fs_pending.data[fs_pending.data_len] = '\0';

	k_sem_give(&fs_resp_sem);
}

/* ---- Zephyr VFS callbacks ---- */

/* File handle storage — map Zephyr file pointer to remote fh */
struct pvcmfs_file {
	uint8_t fh;
};

static int pvcmfs_open(struct fs_file_t *filp, const char *path,
		       fs_mode_t flags)
{
	LOG_INF("pvcmfs open: %s flags=0x%x", path, flags);
	uint32_t oflags = 0;
	if (flags & FS_O_READ) oflags |= 0x01;
	if (flags & FS_O_WRITE) oflags |= 0x02;
	if (flags & FS_O_CREATE) oflags |= 0x04;
	if (flags & FS_O_APPEND) oflags |= 0x08;

	int ret = fs_rpc(PVCM_FS_OPEN, 0, oflags, 0,
			 path, strlen(path), NULL, 0, NULL, 0);
	fs_rpc_cleanup();

	if (ret < 0)
		return ret;

	struct pvcmfs_file *f = k_malloc(sizeof(*f));
	if (!f)
		return -ENOMEM;
	f->fh = fs_pending.fh;
	filp->filep = f;

	return 0;
}

static int pvcmfs_close(struct fs_file_t *filp)
{
	struct pvcmfs_file *f = filp->filep;
	if (!f)
		return -EINVAL;

	int ret = fs_rpc(PVCM_FS_CLOSE, f->fh, 0, 0,
			 NULL, 0, NULL, 0, NULL, 0);
	fs_rpc_cleanup();
	k_free(f);
	filp->filep = NULL;
	return ret;
}

static ssize_t pvcmfs_read(struct fs_file_t *filp, void *buf, size_t len)
{
	struct pvcmfs_file *f = filp->filep;
	if (!f)
		return -EINVAL;

	int ret = fs_rpc(PVCM_FS_READ, f->fh, (uint32_t)len, 0,
			 NULL, 0, NULL, 0, buf, len);

	size_t got = fs_pending.data_len;
	fs_rpc_cleanup();

	if (ret < 0)
		return ret;
	return (ssize_t)got;
}

static ssize_t pvcmfs_write(struct fs_file_t *filp, const void *buf,
			    size_t len)
{
	struct pvcmfs_file *f = filp->filep;
	if (!f)
		return -EINVAL;

	int ret = fs_rpc(PVCM_FS_WRITE, f->fh, 0, 0,
			 NULL, 0, buf, len, NULL, 0);
	fs_rpc_cleanup();

	if (ret < 0)
		return ret;
	return (ssize_t)ret; /* result = bytes written */
}

static int pvcmfs_lseek(struct fs_file_t *filp, off_t off, int whence)
{
	struct pvcmfs_file *f = filp->filep;
	if (!f)
		return -EINVAL;

	int ret = fs_rpc(PVCM_FS_LSEEK, f->fh, (uint32_t)off, (uint32_t)whence,
			 NULL, 0, NULL, 0, NULL, 0);
	fs_rpc_cleanup();
	return ret;
}

static int pvcmfs_truncate(struct fs_file_t *filp, off_t length)
{
	struct pvcmfs_file *f = filp->filep;
	if (!f)
		return -EINVAL;

	int ret = fs_rpc(PVCM_FS_TRUNCATE, f->fh, (uint32_t)length, 0,
			 NULL, 0, NULL, 0, NULL, 0);
	fs_rpc_cleanup();
	return ret;
}

static int pvcmfs_sync(struct fs_file_t *filp)
{
	struct pvcmfs_file *f = filp->filep;
	if (!f)
		return -EINVAL;

	int ret = fs_rpc(PVCM_FS_SYNC, f->fh, 0, 0,
			 NULL, 0, NULL, 0, NULL, 0);
	fs_rpc_cleanup();
	return ret;
}

static int pvcmfs_stat(struct fs_mount_t *mp, const char *path,
		       struct fs_dirent *entry)
{
	struct pvcm_fs_stat st;
	int ret = fs_rpc(PVCM_FS_STAT, 0, 0, 0,
			 path, strlen(path), NULL, 0, &st, sizeof(st));
	fs_rpc_cleanup();

	if (ret < 0)
		return ret;

	entry->type = (st.type == 1) ? FS_DIR_ENTRY_DIR : FS_DIR_ENTRY_FILE;
	entry->size = st.size;

	/* extract filename from path */
	const char *name = strrchr(path, '/');
	name = name ? name + 1 : path;
	strncpy(entry->name, name, sizeof(entry->name) - 1);
	entry->name[sizeof(entry->name) - 1] = '\0';

	return 0;
}

static int pvcmfs_unlink(struct fs_mount_t *mp, const char *path)
{
	int ret = fs_rpc(PVCM_FS_UNLINK, 0, 0, 0,
			 path, strlen(path), NULL, 0, NULL, 0);
	fs_rpc_cleanup();
	return ret;
}

static int pvcmfs_rename(struct fs_mount_t *mp, const char *from,
			 const char *to)
{
	/* pack both paths: from\0to */
	size_t flen = strlen(from);
	size_t tlen = strlen(to);
	size_t total = flen + 1 + tlen;
	char *packed = k_malloc(total);
	if (!packed)
		return -ENOMEM;

	memcpy(packed, from, flen);
	packed[flen] = '\0';
	memcpy(packed + flen + 1, to, tlen);

	int ret = fs_rpc(PVCM_FS_RENAME, 0, 0, 0,
			 packed, total, NULL, 0, NULL, 0);
	fs_rpc_cleanup();
	k_free(packed);
	return ret;
}

static int pvcmfs_mkdir(struct fs_mount_t *mp, const char *path)
{
	int ret = fs_rpc(PVCM_FS_MKDIR, 0, 0, 0,
			 path, strlen(path), NULL, 0, NULL, 0);
	fs_rpc_cleanup();
	return ret;
}

/* Directory handle */
struct pvcmfs_dir {
	uint8_t fh;
};

static int pvcmfs_opendir(struct fs_dir_t *dirp, const char *path)
{
	LOG_INF("opendir: %s", path);
	int ret = fs_rpc(PVCM_FS_OPENDIR, 0, 0, 0,
			 path, strlen(path), NULL, 0, NULL, 0);
	fs_rpc_cleanup();

	if (ret < 0)
		return ret;

	struct pvcmfs_dir *d = k_malloc(sizeof(*d));
	if (!d)
		return -ENOMEM;
	d->fh = fs_pending.fh;
	dirp->dirp = d;
	return 0;
}

static int pvcmfs_readdir(struct fs_dir_t *dirp, struct fs_dirent *entry)
{
	struct pvcmfs_dir *d = dirp->dirp;
	if (!d)
		return -EINVAL;

	/* response data: struct pvcm_fs_stat + name string */
	char buf[sizeof(struct pvcm_fs_stat) + 256];
	int ret = fs_rpc(PVCM_FS_READDIR, d->fh, 0, 0,
			 NULL, 0, NULL, 0, buf, sizeof(buf));

	if (ret < 0 || fs_pending.data_len == 0) {
		/* end of directory or error */
		fs_rpc_cleanup();
		if (ret == 0) {
			entry->name[0] = '\0'; /* Zephyr convention for EOD */
			return 0;
		}
		return ret;
	}

	/* unpack: stat struct + name */
	if (fs_pending.data_len >= sizeof(struct pvcm_fs_stat)) {
		struct pvcm_fs_stat *st = (struct pvcm_fs_stat *)buf;
		entry->type = (st->type == 1) ? FS_DIR_ENTRY_DIR
					      : FS_DIR_ENTRY_FILE;
		entry->size = st->size;

		size_t name_len = fs_pending.data_len - sizeof(struct pvcm_fs_stat);
		if (name_len >= sizeof(entry->name))
			name_len = sizeof(entry->name) - 1;
		memcpy(entry->name, buf + sizeof(struct pvcm_fs_stat), name_len);
		entry->name[name_len] = '\0';
	}

	fs_rpc_cleanup();
	return 0;
}

static int pvcmfs_closedir(struct fs_dir_t *dirp)
{
	struct pvcmfs_dir *d = dirp->dirp;
	if (!d)
		return -EINVAL;

	int ret = fs_rpc(PVCM_FS_CLOSEDIR, d->fh, 0, 0,
			 NULL, 0, NULL, 0, NULL, 0);
	fs_rpc_cleanup();
	k_free(d);
	dirp->dirp = NULL;
	return ret;
}

static int pvcmfs_statvfs(struct fs_mount_t *mp, const char *path,
			  struct fs_statvfs *stat)
{
	/* basic implementation — could be extended */
	stat->f_bsize = 4096;
	stat->f_frsize = 4096;
	stat->f_blocks = 0;
	stat->f_bfree = 0;
	return 0;
}

static int pvcmfs_mount(struct fs_mount_t *mp)
{
	LOG_INF("pvcmfs mount: %s (type=%d)", mp->mnt_point, mp->type);

	/* send MOUNT request with share name as path */
	const char *share = mp->fs_data ? (const char *)mp->fs_data
					: mp->mnt_point;
	int ret = fs_rpc(PVCM_FS_MOUNT, 0, 0, 0,
			 share, strlen(share), NULL, 0, NULL, 0);
	fs_rpc_cleanup();
	return ret;
}

static int pvcmfs_unmount(struct fs_mount_t *mp)
{
	LOG_INF("pvcmfs unmount: %s", mp->mnt_point);

	int ret = fs_rpc(PVCM_FS_UNMOUNT, 0, 0, 0,
			 mp->mnt_point, strlen(mp->mnt_point),
			 NULL, 0, NULL, 0);
	fs_rpc_cleanup();
	return ret;
}

/* ---- VFS registration ---- */

static const struct fs_file_system_t pvcmfs_ops = {
	.open = pvcmfs_open,
	.close = pvcmfs_close,
	.read = pvcmfs_read,
	.write = pvcmfs_write,
	.lseek = pvcmfs_lseek,
	.truncate = pvcmfs_truncate,
	.sync = pvcmfs_sync,
	.opendir = pvcmfs_opendir,
	.readdir = pvcmfs_readdir,
	.closedir = pvcmfs_closedir,
	.mount = pvcmfs_mount,
	.unmount = pvcmfs_unmount,
	.unlink = pvcmfs_unlink,
	.rename = pvcmfs_rename,
	.mkdir = pvcmfs_mkdir,
	.stat = pvcmfs_stat,
	.statvfs = pvcmfs_statvfs,
};

/* Public mount helper */
int pvcm_fs_mount(const char *mount_point, const char *share_name)
{
	static struct fs_mount_t mounts[4]; /* up to 4 shares */
	static int mount_count;

	if (mount_count >= 4)
		return -ENOMEM;

	struct fs_mount_t *mp = &mounts[mount_count];
	mp->type = FS_TYPE_PVCMFS;

	/* copy strings — shell argv pointers are temporary */
	size_t mp_len = strlen(mount_point) + 1;
	size_t sn_len = strlen(share_name) + 1;
	char *mp_copy = k_malloc(mp_len + sn_len);
	if (!mp_copy)
		return -ENOMEM;
	memcpy(mp_copy, mount_point, mp_len);
	memcpy(mp_copy + mp_len, share_name, sn_len);

	mp->mnt_point = mp_copy;
	mp->fs_data = mp_copy + mp_len;

	int ret = fs_mount(mp);
	if (ret == -EBUSY) {
		/* already mounted on MCU — but proxy may have restarted,
		 * so send MOUNT RPC to re-establish the share mapping */
		printk("pvcmfs: %s already mounted, re-syncing proxy\n",
		       mount_point);
		fs_rpc(PVCM_FS_MOUNT, 0, 0, 0,
		       share_name, strlen(share_name), NULL, 0, NULL, 0);
		fs_rpc_cleanup();
		k_free(mp_copy);
		return 0;
	}
	if (ret == 0)
		mount_count++;

	return ret;
}

/* Register filesystem type at boot */
static int pvcmfs_init(void)
{
	int ret = fs_register(FS_TYPE_PVCMFS, &pvcmfs_ops);
	printk("pvcmfs: registered type=%d ret=%d\n", FS_TYPE_PVCMFS, ret);
	return ret;
}

SYS_INIT(pvcmfs_init, POST_KERNEL, 99);
