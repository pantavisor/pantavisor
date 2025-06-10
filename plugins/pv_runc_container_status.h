/*
 * Copyright (c) 2025 Pantacor Ltd.
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
#ifndef PV_RUNC_CONTAINER_STATE_H
#define PV_RUNC_CONTAINER_STATE_H

#include <stddef.h>  // For size_t
#include <stdbool.h> // For bool

// Enum for container status for strong typing
typedef enum {
    pv_runc_container_status_unknown,
    pv_runc_container_status_creating,
    pv_runc_container_status_created,
    pv_runc_container_status_running,
    pv_runc_container_status_stopped
} pv_runc_container_status;

// Struct to hold the parsed container state
typedef struct {
    int pid;
} pv_runc_container_state;

// Function prototypes
// Initializes a pv_runc_container_state struct (sets pointers to NULL, pid to 0, etc.)
void pv_runc_init_container_state(pv_runc_container_state *state);

// Frees memory allocated for a pv_runc_container_state struct
void pv_runc_free_container_state(pv_runc_container_state *state);

// Parses a JSON string into a pv_runc_container_state struct
// Returns true on success, false on failure
bool pv_runc_parse_container_state_json(const char *json_string, pv_runc_container_state *state);

// Reads the entire content of a file into a string
// Returns a dynamically allocated string on success, NULL on failure.
// Caller is responsible for freeing the returned string.
char* pv_runc_read_file_to_string(const char *filepath);

// Reads JSON from a file, parses it, and populates the container state struct.
// Returns true on success, false on failure.
bool pv_runc_parse_container_state_file(const char *filepath, pv_runc_container_state *state);


#endif // PV_RUNC_CONTAINER_STATE_H
