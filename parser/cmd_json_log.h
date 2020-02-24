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
#ifndef __CMD_JSON_LOG_H__
#define __CMD_JSON_LOG_H__

#define JSON_ATTR_SOURCE 	"source"
#define JSON_ATTR_LEVEL 	"level"
#define JSON_ATTR_MSG 		"msg"

#define CMD_JSON_FMT(msg_fmt) 	\
	"{\"" JSON_ATTR_SOURCE "\":\"%s\","\
	"\"" JSON_ATTR_LEVEL "\":%d,"\
	"\"" JSON_ATTR_MSG "\":\""msg_fmt"\"}"

int push_cmd_json_log(char *json_buf);
#endif /*__CMD_JSON_LOG_H__*/
