#include "pvtx_error.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

void pv_pvtx_error_set(struct pv_pvtx_error *err, int code, const char *func,
		       int line, const char *tmpl, ...)
{
	pv_pvtx_error_clear(err);

	int n = 0;
	if (func)
		n = snprintf(err->str, PV_PVTX_ERROR_MAX_LEN, "[%s:%d]: ", func,
			     line);

	va_list list;
	va_start(list, tmpl);
	vsnprintf(err->str + n, PV_PVTX_ERROR_MAX_LEN - n, tmpl, list);
	va_end(list);

	err->code = code;
}

void pv_pvtx_error_clear(struct pv_pvtx_error *err)
{
	memset(err, 0, sizeof(struct pv_pvtx_error));
}