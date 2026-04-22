#include "pvtx_error.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <linux/limits.h>

static void set_error(struct pv_pvtx_error *err, int code, const char *tmpl, va_list list)
{
	pv_pvtx_error_clear(err);
	vsnprintf(err->str, PV_PVTX_ERROR_MAX_LEN, tmpl, list);
	err->code = code;
}

void pv_pvtx_error_set(struct pv_pvtx_error *err, int code, const char *tmpl,
		       ...)
{
	va_list list;
	va_start(list, tmpl);
	set_error(err, code, tmpl, list);
	va_end(list);
}

void pv_pvtx_error_clear(struct pv_pvtx_error *err)
{
	memset(err, 0, sizeof(struct pv_pvtx_error));
}

void pv_pvtx_error_prepend(struct pv_pvtx_error *err, const char *tmpl, ...)
{
	char old_buf[PV_PVTX_ERROR_MAX_LEN] = { 0 };
	memccpy(old_buf, err->str, '\0', PV_PVTX_ERROR_MAX_LEN);

	char new_buf[PV_PVTX_ERROR_MAX_LEN] = { 0 };
	va_list list;
	va_start(list, tmpl);
	vsnprintf(new_buf, PV_PVTX_ERROR_MAX_LEN, tmpl, list);
	va_end(list);

	pv_pvtx_error_set(err, err->code, "%s;\n%s", new_buf, old_buf);
}

void pv_pvtx_error_print(struct pv_pvtx_error *err, const char *name)
{
	fprintf(stderr, "ERROR: %s: %s\n", name, err->str);
}

void pv_pvtx_error_print_raw(const char *name, const char *tmpl, ...)
{
	struct pv_pvtx_error err = {0};
	va_list list;
	va_start(list, tmpl);
	set_error(&err, -1, tmpl, list);
	va_end(list);

	pv_pvtx_error_print(&err, name);
}
