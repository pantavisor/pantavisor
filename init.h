/*
 * Copyright (c) 2017 Pantacor Ltd.
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
#ifndef SC_INIT_H
#define SC_INIT_H

#ifndef CLONE_FS
#  define CLONE_FS                0x00000200
#endif
#ifndef CLONE_NEWNS
#  define CLONE_NEWNS             0x00020000
#endif
#ifndef CLONE_NEWCGROUP
#  define CLONE_NEWCGROUP         0x02000000
#endif
#ifndef CLONE_NEWUTS
#  define CLONE_NEWUTS            0x04000000
#endif
#ifndef CLONE_NEWIPC
#  define CLONE_NEWIPC            0x08000000
#endif
#ifndef CLONE_NEWUSER
#  define CLONE_NEWUSER           0x10000000
#endif
#ifndef CLONE_NEWPID
#  define CLONE_NEWPID            0x20000000
#endif
#ifndef CLONE_NEWNET
#  define CLONE_NEWNET            0x40000000
#endif

#endif
