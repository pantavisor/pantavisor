
#include <stdio.h>
#include <stdlib.h>

#include "json.h"

int main()
{
	struct pv_json_ser js;

	pv_json_ser_init(&js, 16);

	pv_json_ser_object(&js);
	{
		pv_json_ser_key(&js, "one_key_thingy");
		pv_json_ser_string(&js, "this will trigger a buf resize");

		pv_json_ser_object_pop(&js);
	}

	char *buf = pv_json_ser_str(&js);

	printf("buf: %s\n", buf);

	free(buf);

	return 0;
}
