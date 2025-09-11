#include "pvtx_error.h"
#include "utils/fs.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <linux/limits.h>

void pv_pvtx_error_set(struct pv_pvtx_error *err, int code, const char *file,
		       int line, const char *tmpl, ...)
{
	pv_pvtx_error_clear(err);

	va_list list;
	va_start(list, tmpl);
	int len = vsnprintf(err->str, PV_PVTX_ERROR_MAX_LEN, tmpl, list);
	va_end(list);

	if (file && len < PV_PVTX_ERROR_MAX_LEN) {
		char bname[NAME_MAX] = { 0 };
		pv_fs_basename(file, bname);

		snprintf(err->str + len, PV_PVTX_ERROR_MAX_LEN - len,
			 "\n(%s:%d)", bname, line);
	}

	err->code = code;
}

void pv_pvtx_error_clear(struct pv_pvtx_error *err)
{
	memset(err, 0, sizeof(struct pv_pvtx_error));
}

void pv_pvtx_error_prepend(struct pv_pvtx_error *err, const char *file,
			   int line, const char *tmpl, ...)
{
	char old_buf[PV_PVTX_ERROR_MAX_LEN] = { 0 };
	memccpy(old_buf, err->str, '\0', PV_PVTX_ERROR_MAX_LEN);

	char new_buf[PV_PVTX_ERROR_MAX_LEN] = { 0 };
	va_list list;
	va_start(list, tmpl);
	vsnprintf(new_buf, PV_PVTX_ERROR_MAX_LEN, tmpl, list);
	va_end(list);

	pv_pvtx_error_set(err, err->code, file, line, "%s: %s", new_buf,
			  old_buf);
}