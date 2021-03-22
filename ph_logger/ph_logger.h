/*
 * Copyright (c) 2020 Pantacor Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef __PH_LOGGER_H__
#define __PH_LOGGER_H__
#include <stdarg.h>
#include <stdbool.h>
#include <inttypes.h>
#include "../pantavisor.h"
#define PH_LOGGER_JSON_FORMAT     "{ \"tsec\": %"PRId64", \"tnano\": %"PRId32",\
\"lvl\": \"%s\", \"src\": \"%s\",\"plat\":\"%s\",\
\"rev\": \"%s\" , \"msg\": \"%s\" }"

#define PH_LOGGER_POS_XATTR 	"trusted.ph.logger.pos"
enum {
	PH_LOGGER_V1,
	/*Add new versions before this*/
	PH_LOGGER_MAX_HANDLERS
};
#ifdef DEBUG
#define WARN_ONCE(msg, args...) 	\
do {\
	static bool __warned = false; 	\
	if (! __warned) { 		\
		printf(msg, ##args); 	\
		__warned = true; 	\
	}\
}while(0)
#else
#define WARN_ONCE(msg, args...) 	
#endif


#define PH_LOGGER_WRITE_TIMEOUT 	(5)
/*
 * Write Semantics for Version 1
 * v1 has the following message format in buffer
 * level (int),
 * platform (NULL terminated string),
 * source (NULL terminated string),
 * len (length of the data in buf)
 * args should contain the valid addresses for the above in the order they appear above.
 */

/*
 * Read semantics for Version 1
 * v1 has the following message format in buffer
 * level (int),
 * platform (NULL terminated string),
 * source (NULL terminated string),
 * args should contain the valid addresses for the above in the order they appear above.
 */

struct ph_logger_msg {
	int version;
	int len;
	char buffer[0];
};

typedef int (*ph_logger_handler_t)(struct ph_logger_msg*, char *buf, va_list args);

typedef int (*ph_logger_file_rw_handler_t)(struct ph_logger_msg*, const char *log_dir, char *rev);


/*
 * Make ph_logger_msg->buffer from buf by placing correct values in ph_logger
 * _msg structure.
 * use ph_logger_msg->len for the length of the buffer to write..
 * returns number of bytes written on success.
 * */
int ph_logger_write_bytes(struct ph_logger_msg *, const char *buf, ...);
/*
 * reads the message from a ph_logger_msg.
 * buf is the output buffer,
 * use ph_logger_msg->len with the max length for buffer available.
 *      on return it contains the actual bytes read.
 * returns 0 on success.
 * */
int ph_logger_read_bytes(struct ph_logger_msg *, char *buf, ...);

int ph_logger_init(const char *sock_path);
void ph_logger_toggle(struct pantavisor *pv, char *rev);
void ph_logger_stop(struct pantavisor *pv);
#endif /* __PH_LOGGER_H__ */
