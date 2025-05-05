#include "logserver_sink.h"

#include <stdlib.h>

struct pv_logserver_sink *
pv_logserver_sink_new(const char *name,
		      int (*add)(const struct pv_logserver_sink *sink,
				 const struct pv_logserver_log *log),
		      void (*free)(struct pv_logserver_sink *sink), void *priv)
{
	struct pv_logserver_sink *sink =
		calloc(1, sizeof(struct pv_logserver_sink));

	if (!sink)
		return NULL;

	sink->name = strdup(name);
	if (!sink->name) {
		free(sink);
		return NULL;
	}

	sink->add = add;
	sink->free = free;
	sink->priv = priv;
	dl_list_init(&sink->list);

	return sink;
}
