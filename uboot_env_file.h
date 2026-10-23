#ifndef PV_UBOOT_ENV_FILE_H
#define PV_UBOOT_ENV_FILE_H

/*
 * Clear pv_trying in the pv.env file the U-Boot boot script keeps, so a
 * devmode-requested reboot boots the revision again instead of falling back.
 * Returns 0 when rewritten or nothing to rewrite, -1 on failure.
 */
int pv_uboot_env_file_clear_trying(void);

#endif
