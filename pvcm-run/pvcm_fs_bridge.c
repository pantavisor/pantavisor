/*
 * pvcm-run filesystem bridge
 *
 * Serves Linux directories to the MCU. Each --fs-share maps a
 * share name to a Linux directory. MCU mounts shares and performs
 * file operations via FS_REQ/FS_DATA/FS_END frames.
 *
 * Security: paths are resolved relative to the share root.
 * Traversal via ".." is rejected.
 *
 * SPDX-License-Identifier: MIT
 */

#include "pvcm_fs_bridge.h"

#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

/* ---- Share table ---- */

struct fs_share {
	char name[64];         /* share name (matches MCU mount) */
	char root[256];        /* Linux directory path */
};

static struct fs_share shares[PVCM_MAX_FS_SHARES];
static int num_shares;

int pvcm_fs_bridge_add_share(const char *spec)
{
	if (num_shares >= PVCM_MAX_FS_SHARES)
		return -1;

	const char *eq = strchr(spec, '=');
	if (!eq)
		return -1;

	struct fs_share *s = &shares[num_shares];
	size_t nlen = eq - spec;
	if (nlen >= sizeof(s->name))
		nlen = sizeof(s->name) - 1;
	memcpy(s->name, spec, nlen);
	s->name[nlen] = '\0';

	strncpy(s->root, eq + 1, sizeof(s->root) - 1);

	fprintf(stdout, "[fs-bridge] share: %s -> %s\n", s->name, s->root);
	num_shares++;
	return 0;
}

static const struct fs_share *find_share(const char *name)
{
	for (int i = 0; i < num_shares; i++) {
		if (strcmp(shares[i].name, name) == 0)
			return &shares[i];
	}
	return NULL;
}

/* ---- File handle table ---- */

#define MAX_FH 16

static struct {
	int fd;                /* Linux fd or -1 */
	DIR *dir;              /* opendir handle or NULL */
	const struct fs_share *share;
	bool active;
} fh_table[MAX_FH];

static int alloc_fh(void)
{
	for (int i = 1; i < MAX_FH; i++) { /* 0 reserved */
		if (!fh_table[i].active)
			return i;
	}
	return -1;
}

static void free_fh(int fh)
{
	if (fh < 0 || fh >= MAX_FH)
		return;
	if (fh_table[fh].fd >= 0) {
		close(fh_table[fh].fd);
		fh_table[fh].fd = -1;
	}
	if (fh_table[fh].dir) {
		closedir(fh_table[fh].dir);
		fh_table[fh].dir = NULL;
	}
	fh_table[fh].active = false;
}

/* ---- Path resolution ---- */

/* Active share for path resolution (set by MOUNT) */
static const struct fs_share *mounted_share;

static int resolve_path(const char *mcu_path, char *out, size_t out_size)
{
	if (!mounted_share) {
		fprintf(stderr, "[fs-bridge] no share mounted\n");
		return -1;
	}

	/* reject path traversal */
	if (strstr(mcu_path, "..")) {
		fprintf(stderr, "[fs-bridge] path traversal rejected: %s\n",
			mcu_path);
		return -1;
	}

	/* strip mount point prefix: MCU sends "/storage/foo",
	 * share name is "storage" — skip leading / then strip name */
	const char *rel = mcu_path;
	if (rel[0] == '/')
		rel++;
	size_t mnt_len = strlen(mounted_share->name);
	if (strncmp(rel, mounted_share->name, mnt_len) == 0) {
		rel += mnt_len;
		if (rel[0] == '/')
			rel++;
	}

	if (rel[0] == '\0')
		snprintf(out, out_size, "%s", mounted_share->root);
	else
		snprintf(out, out_size, "%s/%s", mounted_share->root, rel);
	return 0;
}

/* ---- Transport ---- */

static struct pvcm_transport *fs_transport;

static void send_fs_resp(uint8_t req_id, uint8_t fs_op, uint8_t fh,
			 int32_t result, uint32_t data_len)
{
	pvcm_fs_resp_t resp = {
		.op = PVCM_OP_FS_RESP,
		.req_id = req_id,
		.fs_op = fs_op,
		.fh = fh,
		.result = result,
		.data_len = data_len,
	};
	fs_transport->send_frame(fs_transport, &resp,
				 sizeof(resp) - sizeof(uint32_t));
}

static void send_fs_data_frames(uint8_t req_id, const void *data,
				size_t len)
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
		memcpy(frame.data, (const uint8_t *)data + off, chunk);
		fs_transport->send_frame(fs_transport, &frame, 4 + chunk);
		off += chunk;
	}
}

static void send_fs_end_frame(uint8_t req_id)
{
	pvcm_fs_end_t end = {
		.op = PVCM_OP_FS_END,
		.req_id = req_id,
	};
	fs_transport->send_frame(fs_transport, &end,
				 sizeof(end) - sizeof(uint32_t));
}

/* ---- Pending request assembly ---- */

static struct {
	uint8_t req_id;
	uint8_t fs_op;
	uint8_t fh;
	uint32_t arg1, arg2;
	uint16_t path_len;
	uint32_t data_len;
	char *buf;             /* malloc'd: path + write data */
	size_t received;
	size_t expected;       /* path_len + data_len */
	bool active;
} fs_rx;

static void fs_rx_reset(void)
{
	free(fs_rx.buf);
	memset(&fs_rx, 0, sizeof(fs_rx));
}

/* ---- Process completed FS request ---- */

static void process_fs_request(void)
{
	uint8_t rid = fs_rx.req_id;
	uint8_t op = fs_rx.fs_op;
	uint8_t fh = fs_rx.fh;

	/* extract path from buffer */
	char path[512] = "";
	if (fs_rx.path_len > 0 && fs_rx.buf) {
		size_t plen = fs_rx.path_len;
		if (plen >= sizeof(path))
			plen = sizeof(path) - 1;
		memcpy(path, fs_rx.buf, plen);
		path[plen] = '\0';
	}

	/* extract write data pointer */
	const char *write_data = NULL;
	size_t write_len = 0;
	if (fs_rx.data_len > 0 && fs_rx.buf) {
		write_data = fs_rx.buf + fs_rx.path_len;
		write_len = fs_rx.data_len;
	}

	char resolved[512];

	switch (op) {
	case PVCM_FS_MOUNT: {
		const struct fs_share *s = find_share(path);
		if (!s) {
			fprintf(stderr, "[fs-bridge] unknown share: %s\n", path);
			send_fs_resp(rid, op, 0, -ENOENT, 0);
			break;
		}
		mounted_share = s;
		fprintf(stdout, "[fs-bridge] mounted: %s -> %s\n",
			s->name, s->root);
		send_fs_resp(rid, op, 0, 0, 0);
		break;
	}

	case PVCM_FS_UNMOUNT:
		mounted_share = NULL;
		send_fs_resp(rid, op, 0, 0, 0);
		break;

	case PVCM_FS_OPEN: {
		if (resolve_path(path, resolved, sizeof(resolved)) < 0) {
			send_fs_resp(rid, op, 0, -EINVAL, 0);
			break;
		}
		int slot = alloc_fh();
		if (slot < 0) {
			send_fs_resp(rid, op, 0, -ENFILE, 0);
			break;
		}
		int flags = 0;
		if ((fs_rx.arg1 & 0x03) == 0x03) flags = O_RDWR;
		else if (fs_rx.arg1 & 0x02) flags = O_WRONLY;
		else flags = O_RDONLY;
		if (fs_rx.arg1 & 0x04) flags |= O_CREAT;
		if (fs_rx.arg1 & 0x08) flags |= O_APPEND;

		int fd = open(resolved, flags, 0644);
		if (fd < 0) {
			send_fs_resp(rid, op, 0, -errno, 0);
			break;
		}
		fh_table[slot].fd = fd;
		fh_table[slot].active = true;
		fh_table[slot].share = mounted_share;
		fprintf(stdout, "[fs-bridge] open: %s -> fh=%d\n",
			resolved, slot);
		send_fs_resp(rid, op, (uint8_t)slot, 0, 0);
		break;
	}

	case PVCM_FS_CLOSE:
		if (fh < MAX_FH && fh_table[fh].active) {
			free_fh(fh);
			send_fs_resp(rid, op, fh, 0, 0);
		} else {
			send_fs_resp(rid, op, fh, -EBADF, 0);
		}
		break;

	case PVCM_FS_READ: {
		if (fh >= MAX_FH || !fh_table[fh].active || fh_table[fh].fd < 0) {
			send_fs_resp(rid, op, fh, -EBADF, 0);
			break;
		}
		size_t count = fs_rx.arg1;
		char *rbuf = malloc(count);
		if (!rbuf) {
			send_fs_resp(rid, op, fh, -ENOMEM, 0);
			break;
		}
		ssize_t n = read(fh_table[fh].fd, rbuf, count);
		if (n < 0) {
			send_fs_resp(rid, op, fh, -errno, 0);
		} else {
			send_fs_resp(rid, op, fh, (int32_t)n, (uint32_t)n);
			if (n > 0)
				send_fs_data_frames(rid, rbuf, n);
			send_fs_end_frame(rid);
		}
		free(rbuf);
		break;
	}

	case PVCM_FS_WRITE: {
		if (fh >= MAX_FH || !fh_table[fh].active || fh_table[fh].fd < 0) {
			send_fs_resp(rid, op, fh, -EBADF, 0);
			break;
		}
		ssize_t n = write(fh_table[fh].fd, write_data, write_len);
		send_fs_resp(rid, op, fh, n < 0 ? -errno : (int32_t)n, 0);
		break;
	}

	case PVCM_FS_LSEEK: {
		if (fh >= MAX_FH || !fh_table[fh].active) {
			send_fs_resp(rid, op, fh, -EBADF, 0);
			break;
		}
		off_t pos = lseek(fh_table[fh].fd, (off_t)fs_rx.arg1,
				  (int)fs_rx.arg2);
		send_fs_resp(rid, op, fh, pos < 0 ? -errno : (int32_t)pos, 0);
		break;
	}

	case PVCM_FS_TRUNCATE: {
		if (fh >= MAX_FH || !fh_table[fh].active) {
			send_fs_resp(rid, op, fh, -EBADF, 0);
			break;
		}
		int ret = ftruncate(fh_table[fh].fd, (off_t)fs_rx.arg1);
		send_fs_resp(rid, op, fh, ret < 0 ? -errno : 0, 0);
		break;
	}

	case PVCM_FS_SYNC: {
		if (fh >= MAX_FH || !fh_table[fh].active) {
			send_fs_resp(rid, op, fh, -EBADF, 0);
			break;
		}
		int ret = fsync(fh_table[fh].fd);
		send_fs_resp(rid, op, fh, ret < 0 ? -errno : 0, 0);
		break;
	}

	case PVCM_FS_STAT: {
		if (resolve_path(path, resolved, sizeof(resolved)) < 0) {
			send_fs_resp(rid, op, 0, -EINVAL, 0);
			break;
		}
		struct stat st;
		if (stat(resolved, &st) < 0) {
			send_fs_resp(rid, op, 0, -errno, 0);
			break;
		}
		struct pvcm_fs_stat pst = {
			.type = S_ISDIR(st.st_mode) ? 1 : 0,
			.size = (uint32_t)st.st_size,
		};
		send_fs_resp(rid, op, 0, 0, sizeof(pst));
		send_fs_data_frames(rid, &pst, sizeof(pst));
		send_fs_end_frame(rid);
		break;
	}

	case PVCM_FS_UNLINK: {
		if (resolve_path(path, resolved, sizeof(resolved)) < 0) {
			send_fs_resp(rid, op, 0, -EINVAL, 0);
			break;
		}
		int ret = unlink(resolved);
		send_fs_resp(rid, op, 0, ret < 0 ? -errno : 0, 0);
		break;
	}

	case PVCM_FS_RENAME: {
		/* path contains from\0to */
		const char *from_path = path;
		const char *to_path = path + strlen(path) + 1;

		char resolved_from[512], resolved_to[512];
		if (resolve_path(from_path, resolved_from, sizeof(resolved_from)) < 0 ||
		    resolve_path(to_path, resolved_to, sizeof(resolved_to)) < 0) {
			send_fs_resp(rid, op, 0, -EINVAL, 0);
			break;
		}
		int ret = rename(resolved_from, resolved_to);
		send_fs_resp(rid, op, 0, ret < 0 ? -errno : 0, 0);
		break;
	}

	case PVCM_FS_MKDIR: {
		if (resolve_path(path, resolved, sizeof(resolved)) < 0) {
			send_fs_resp(rid, op, 0, -EINVAL, 0);
			break;
		}
		int ret = mkdir(resolved, 0755);
		send_fs_resp(rid, op, 0, ret < 0 ? -errno : 0, 0);
		break;
	}

	case PVCM_FS_OPENDIR: {
		if (resolve_path(path, resolved, sizeof(resolved)) < 0) {
			send_fs_resp(rid, op, 0, -EINVAL, 0);
			break;
		}
		int slot = alloc_fh();
		if (slot < 0) {
			send_fs_resp(rid, op, 0, -ENFILE, 0);
			break;
		}
		DIR *d = opendir(resolved);
		if (!d) {
			send_fs_resp(rid, op, 0, -errno, 0);
			break;
		}
		fh_table[slot].dir = d;
		fh_table[slot].fd = -1;
		fh_table[slot].active = true;
		fh_table[slot].share = mounted_share;
		fprintf(stdout, "[fs-bridge] opendir: %s -> fh=%d\n",
			resolved, slot);
		send_fs_resp(rid, op, (uint8_t)slot, 0, 0);
		break;
	}

	case PVCM_FS_READDIR: {
		if (fh >= MAX_FH || !fh_table[fh].active || !fh_table[fh].dir) {
			send_fs_resp(rid, op, fh, -EBADF, 0);
			break;
		}
		struct dirent *ent = readdir(fh_table[fh].dir);
		if (!ent) {
			/* end of directory */
			send_fs_resp(rid, op, fh, 0, 0);
			break;
		}
		/* skip . and .. */
		while (ent && (strcmp(ent->d_name, ".") == 0 ||
			       strcmp(ent->d_name, "..") == 0))
			ent = readdir(fh_table[fh].dir);
		if (!ent) {
			send_fs_resp(rid, op, fh, 0, 0);
			break;
		}

		/* pack: struct pvcm_fs_stat + name */
		struct pvcm_fs_stat pst = {
			.type = (ent->d_type == DT_DIR) ? 1 : 0,
			.size = 0, /* would need stat() for size */
		};
		size_t name_len = strlen(ent->d_name);
		size_t total = sizeof(pst) + name_len;
		char *buf = malloc(total);
		if (!buf) {
			send_fs_resp(rid, op, fh, -ENOMEM, 0);
			break;
		}
		memcpy(buf, &pst, sizeof(pst));
		memcpy(buf + sizeof(pst), ent->d_name, name_len);

		send_fs_resp(rid, op, fh, 0, (uint32_t)total);
		send_fs_data_frames(rid, buf, total);
		send_fs_end_frame(rid);
		free(buf);
		break;
	}

	case PVCM_FS_CLOSEDIR:
		if (fh < MAX_FH && fh_table[fh].active && fh_table[fh].dir) {
			free_fh(fh);
			send_fs_resp(rid, op, fh, 0, 0);
		} else {
			send_fs_resp(rid, op, fh, -EBADF, 0);
		}
		break;

	default:
		fprintf(stderr, "[fs-bridge] unknown fs_op=%d\n", op);
		send_fs_resp(rid, op, fh, -ENOSYS, 0);
		break;
	}

	fs_rx_reset();
}

/* ---- Public frame handlers ---- */

int pvcm_fs_bridge_init(struct pvcm_transport *t)
{
	fs_transport = t;
	memset(fh_table, 0, sizeof(fh_table));
	for (int i = 0; i < MAX_FH; i++)
		fh_table[i].fd = -1;
	return 0;
}

int pvcm_fs_bridge_on_req(struct pvcm_transport *t,
			   const uint8_t *buf, int len)
{
	const pvcm_fs_req_t *req = (const pvcm_fs_req_t *)buf;

	fs_rx_reset();
	fs_rx.req_id = req->req_id;
	fs_rx.fs_op = req->fs_op;
	fs_rx.fh = req->fh;
	fs_rx.arg1 = req->arg1;
	fs_rx.arg2 = req->arg2;
	fs_rx.path_len = req->path_len;
	fs_rx.data_len = req->data_len;
	fs_rx.expected = req->path_len + req->data_len;
	fs_rx.active = true;

	if (fs_rx.expected > 0) {
		fs_rx.buf = malloc(fs_rx.expected + 1);
		if (!fs_rx.buf) {
			send_fs_resp(req->req_id, req->fs_op, req->fh,
				     -ENOMEM, 0);
			fs_rx_reset();
			return -1;
		}
		fs_rx.buf[0] = '\0';
	} else {
		/* no data — process immediately */
		process_fs_request();
	}

	return 0;
}

int pvcm_fs_bridge_on_data(struct pvcm_transport *t,
			    const uint8_t *buf, int len)
{
	if (!fs_rx.active || !fs_rx.buf)
		return 0;

	const pvcm_fs_data_t *d = (const pvcm_fs_data_t *)buf;
	if (d->req_id != fs_rx.req_id)
		return 0;

	size_t chunk = d->len;
	if (fs_rx.received + chunk > fs_rx.expected)
		chunk = fs_rx.expected - fs_rx.received;

	memcpy(fs_rx.buf + fs_rx.received, d->data, chunk);
	fs_rx.received += chunk;
	fs_rx.buf[fs_rx.received] = '\0';

	return 0;
}

int pvcm_fs_bridge_on_end(struct pvcm_transport *t,
			   const uint8_t *buf, int len)
{
	if (!fs_rx.active)
		return 0;

	uint8_t req_id = buf[1];
	if (req_id != fs_rx.req_id)
		return 0;

	process_fs_request();
	return 0;
}
