#include "filesystem.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>
static void close_fd(int *fd)
{
    if (!fd || *fd < 0)
        return;

    close(*fd);
    *fd = -1;
}

bool pv_fs_path_exist(const char *path)
{
    return access(path, F_OK) == 0;
}

bool pv_fs_path_is_directory(const char *path)
{
    DIR *tmp = opendir(path);
    if (tmp) {
        closedir(tmp);
        return true;
    }

    return false;
}

static int get_directory(char *dir, const char *path)
{
    if (!pv_fs_path_exist(path)) {
        dir = NULL;
        return -1;
    }

    if (pv_fs_path_is_directory(path)) {
        strncpy(dir, path, strnlen(path, PATH_MAX));
        return 0;
    } else if (errno == ENOTDIR) {
        char copy[PATH_MAX];
        strncpy(copy, path, strnlen(path, PATH_MAX));

        char *tmp = dirname(copy);
        strncpy(dir, tmp, strnlen(path, PATH_MAX));
    }
    return 0;
}

void pv_fs_path_sync(const char *path)
{
    char dir[PATH_MAX] = { 0 };

    if (get_directory(dir, path) != 0)
        return;

    int fd = open(dir, O_RDONLY);
    if (fd > -1) {
        fsync(fd);
        close(fd);
    }
}

int pv_fs_mkdir_p(const char *path, mode_t mode)
{
    if (!path)
        return -1;

    if (pv_fs_path_exist(path)) {
        errno = EEXIST;
        return -1;
    }

    if (errno != 0 && errno != ENOENT)
        return -1;

    char cur_path[PATH_MAX];

    size_t created = 0;
    unsigned long i = 0;
    while (path[i]) {
        if (path[i] == '/') {
            memcpy(cur_path, path, i + 1);
            cur_path[i + 2] = '\0';
            if (mkdir(cur_path, mode) != 0 && errno != EEXIST)
                return -1;
            created = i + 1;
        }
        ++i;
    }

    // create the last directory, this happend when the given path
    // doesn't finish with '/'
    if (created < strlen(path)) {
        if (mkdir(path, mode) != 0 && errno != EEXIST)
            return -1;
    }

    return 0;
}

void pv_fs_path_join(char *buf, int size, ...)
{
    char fmt[PATH_MAX] = { 0 };

    for (int i = 0; i < size; ++i) {
        fmt[i * 3 + 0] = '%';
        fmt[i * 3 + 1] = 's';
        fmt[i * 3 + 2] = '/';
    }

    va_list list;
    va_start(list, size);

    vsnprintf(buf, PATH_MAX, fmt, list);
    buf[strnlen(buf, PATH_MAX) - 1] = '\0';

    va_end(list);
}
int pv_fs_path_remove(const char *path, bool recursive)
{
    if (!recursive) {
        return remove(path);
    }

    struct dirent **arr = NULL;
    int n = scandir(path, &arr, NULL, alphasort);

    for (int i = 0; i < n; ++i) {
        // discard . and .. from scandir
        if (!strcmp(arr[i]->d_name, ".") || !strcmp(arr[i]->d_name, ".."))
            goto free_dir;

        char new_path[PATH_MAX] = { 0 };
        pv_fs_path_join(new_path, 2, path, arr[i]->d_name);

        if (arr[i]->d_type == DT_DIR)
            pv_fs_path_remove(new_path, true);
        else
            pv_fs_path_remove(new_path, false);

free_dir:
        free(arr[i]);
    }
    int ret = remove(path);
    free(arr);

    return ret;
}
int pv_fs_path_rename(const char *src_path, const char *dst_path)
{
    pv_fs_path_sync(src_path);

    int ret = rename(src_path, dst_path);
    if (ret < 0)
        return ret;

    pv_fs_path_sync(dst_path);
    return 0;
}
int pv_fs_file_tmp(char *tmp, const char *fname)
{
    if (!fname)
        return -1;

    size_t size = strnlen(fname, PATH_MAX) + 5;

    if (size > PATH_MAX) {
        errno = ENAMETOOLONG;
        return -1;
    }

    snprintf(tmp, size, "%s.tmp", fname);
    return 0;
}

int pv_fs_file_save(const char *fname, const char *data, mode_t mode)
{
    char tmp[PATH_MAX] = { 0 };
    if (pv_fs_file_tmp(tmp, fname) != 0)
        return -1;

    int ret = -1;
    int fd = open(tmp, O_CREAT | O_WRONLY | O_TRUNC | O_SYNC, mode);
    if (fd < 0)
        goto out;

    if (write(fd, data, strlen(data)) < 0)
        goto out;

    close_fd(&fd);

    ret = pv_fs_path_rename(tmp, fname);

out:
    if (fd > 0)
        close_fd(&fd);

    ret = pv_fs_path_remove(tmp, false);
    pv_fs_path_sync(tmp);

    return ret;
}
ssize_t pv_fs_file_copy_from_fd(int src, int dst, bool close_src)
{
    lseek(src, 0, SEEK_SET);
    lseek(dst, 0, SEEK_SET);

    char buf[4096] = { 0 };
    ssize_t read_bytes = 0;
    ssize_t write_bytes = 0;

    while (read_bytes = read(src, buf, 4096), read_bytes > 0)
        write_bytes += write(dst, buf, read_bytes);

    if (close_src)
        close_fd(&src);

    return write_bytes;
}

int pv_fs_file_copy_from_path(const char *src, const char *dst, mode_t mode)
{
    if (!pv_fs_path_exist(src))
        return -1;

    char tmp_path[PATH_MAX] = { 0 };
    if (pv_fs_file_tmp(tmp_path, src) != 0)
        return -1;

    int tmp_fd = open(tmp_path, O_CREAT | O_WRONLY | O_TRUNC, mode);
    if (tmp_fd < 0)
        return -1;

    int src_fd = open(src, O_RDONLY, 0);
    if (src < 0)
        goto out;

    pv_fs_file_copy_from_fd(src_fd, tmp_fd, true);
    close_fd(&tmp_fd);

    int ret = pv_fs_path_rename(tmp_path, dst);
    if (ret < 0)
        goto out;

out:
    if (src_fd > -1)
        close_fd(&src_fd);

    if (tmp_fd > -1)
        close_fd(&tmp_fd);

    if (pv_fs_path_exist(tmp_path))
        pv_fs_path_remove(tmp_path, false);

    pv_fs_path_sync(src);
    pv_fs_path_sync(dst);

    return ret;
}

size_t pv_fs_path_get_size(const char *path)
{
    struct stat st;

    stat(path, &st);
    return st.st_size;
}

int pv_fs_file_get_xattr(char *value, size_t size, const char *fname, const char *attr)
{
    ssize_t cur_size = getxattr(fname, attr, value, size);
    return cur_size == size ? 0 : -1;
}

char *pv_fs_file_get_xattr_dup(const char *fname, const char *attr)
{
    ssize_t size = getxattr(fname, attr, NULL, 0);
    if (size < 1)
        return NULL;

    char *val = malloc(size);
    if (!val)
        return NULL;

    ssize_t cur_size = getxattr(fname, attr, val, size);

    if (cur_size != size) {
        free(val);
        return NULL;
    }

    return val;
}
