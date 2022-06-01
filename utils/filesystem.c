#include <dirent.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
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
