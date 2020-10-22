#ifndef __PV_LOGGER_H_
#define __PV_LOGGER_H_
#include "pantavisor.h"

struct pv_log_info {
	char *logfile;
	char *name;
	struct dl_list next;
	void (*on_logger_closed)(struct pv_log_info*);
	off_t truncate_size;
	bool islxc;
	pid_t logger_pid;
	const char*(*pv_log_get_config_item)
		(struct pv_logger_config *config, const char *key);
	struct pv_platform *platform;
};

int start_pvlogger(struct pv_log_info *log_info, const char *platform);

void pv_log_info_free(struct pv_log_info * l);

/*
 * user.* attributes are available usually for most file systems.
 * user. prefix is hence necessary! Otherwise filesystem(s) complaint
 * of ENOTSUP.
 * */
#define PV_LOGGER_POS_XATTR 	"trusted.pv.logger.pos"
#define PV_LOGGER_FILE_WAIT_TIMEOUT 	(5)
#endif  /*__PV_LOGGER_H_*/
