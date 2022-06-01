#include <dirent.h>
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

