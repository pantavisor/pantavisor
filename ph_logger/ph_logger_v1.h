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
#include <stdio.h>
#include <stdarg.h>
#include "ph_logger.h"
/*
 * v1 has the following message format in buffer
 * level (int),
 * platform (NULL terminated string),
 * source (NULL terminated string),
 *
 * args should contain the valid addresses for the above in the order they appear above.
 */
int ph_logger_read_handler_v1(struct ph_logger_msg *ph_logger_msg, char *buf, va_list args);

/*
 * v1 has the following message format in buffer
 * level (int),
 * platform (NULL terminated string),
 * source (NULL terminated string),
 * len (length of the data in buf)
 * args should contain the valid addresses for the above in the order they appear above.
 */
int ph_logger_write_handler_v1(struct ph_logger_msg *ph_logger_msg, char *buf, va_list args);

int ph_logger_write_to_file_handler_v1(struct ph_logger_msg *ph_logger_msg, const char *log_dir, char *rev);

