#ifndef __PV_LOGGER_H_
#define __PV_LOGGER_H_
#include "pantavisor.h"
int start_pvlogger(struct pv_log_info *log_info, const char *platform);

/*
 * user.* attributes are available usually for most file systems.
 * user. prefix is hence necessary! Otherwise filesystem(s) complaint
 * of ENOTSUP.
 * */
#define PV_LOGGER_POS_XATTR 	"trusted.pv.logger.pos"
#define PV_LOGGER_FILE_WAIT_TIMEOUT 	(5)
#endif  /*__PV_LOGGER_H_*/
