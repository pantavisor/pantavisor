#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/xconnect.h"

#define MODULE_NAME "pvx-drm"

static int drm_on_link_added(struct pvx_link *link)
{
    printf("%s: Adding DRM link for %s (role: %s)\n", MODULE_NAME, link->consumer, link->role);
    printf("%s: Target: %s, Provider Node: %s\n", MODULE_NAME, link->consumer_socket, link->provider_socket);
    
    // Future: pvx_helper_inject_devnode(link->consumer_socket, link->consumer_pid, ...);
    
    return 0;
}

struct pvx_plugin pvx_plugin_drm = {
    .type = "drm",
    .on_link_added = drm_on_link_added,
    .on_accept = NULL
};

