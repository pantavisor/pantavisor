#ifndef SC_LXC_H
#define SC_LXC_H

extern int lxc_log_init(const char *name, const char *file,
			const char *priority, const char *prefix, int quiet,
			const char *lxcpath);

void* start_lxc_container(char *name, char *conf_file, void *data);
void* stop_lxc_container(char *name, char *conf_file, void *data);

#endif
