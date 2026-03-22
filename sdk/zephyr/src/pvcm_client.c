/*
 * PVCM REST Client -- optional REST API client
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <pantavisor/pvcm.h>
#include <pantavisor/pvcm_protocol.h>

LOG_MODULE_REGISTER(pvcm_client, CONFIG_LOG_DEFAULT_LEVEL);

/* TODO: implement pvcm_get/post/put/delete */

int pvcm_get(const char *path, pvcm_rest_cb_t cb, void *ctx)
{
	ARG_UNUSED(path);
	ARG_UNUSED(cb);
	ARG_UNUSED(ctx);
	return -ENOTSUP;
}

int pvcm_post(const char *path, const char *body,
	      pvcm_rest_cb_t cb, void *ctx)
{
	ARG_UNUSED(path);
	ARG_UNUSED(body);
	ARG_UNUSED(cb);
	ARG_UNUSED(ctx);
	return -ENOTSUP;
}

int pvcm_put(const char *path, const char *body,
	     pvcm_rest_cb_t cb, void *ctx)
{
	ARG_UNUSED(path);
	ARG_UNUSED(body);
	ARG_UNUSED(cb);
	ARG_UNUSED(ctx);
	return -ENOTSUP;
}

int pvcm_delete(const char *path, pvcm_rest_cb_t cb, void *ctx)
{
	ARG_UNUSED(path);
	ARG_UNUSED(cb);
	ARG_UNUSED(ctx);
	return -ENOTSUP;
}
