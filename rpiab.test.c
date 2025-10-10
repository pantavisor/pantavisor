/*
 * Copyright (c) 2023-2024 Pantacor Ltd.
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

#ifndef PVTEST
#define PVTEST
#endif

#include "rpiab.c"
#include "state.h"

#include "update/update_struct.h"

int main()
{
	rpiab_init();

	struct pv_state state_mock = { .rev = "1",
				       .bsp = { .img.rpiab = {
							.bootimg = "/test",
						} } };

	struct struct pv_update update_mock = { .pending = &state_mock };

	printf("=== _rpiab_install_trybootimg ===\n");

	if (_rpiab_install_trybootimg(&state_mock)) {
		pv_log(ERROR, "Error installing tryboot image.");
		return -1;
	}

	printf("=== _rpiab_setrev_trybootimg ===\n");
	if (_rpiab_setrev_trybootimg(&state_mock)) {
		pv_log(ERROR, "Error setting pv_rev in tryboot");
		return -1;
	}
	return 0;
}
