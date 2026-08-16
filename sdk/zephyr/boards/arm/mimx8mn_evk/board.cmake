#
# Copyright (c) 2024-2026 Pantacor Ltd.
#
# SPDX-License-Identifier: Apache-2.0
#

board_set_debugger_ifnset(jlink)
board_set_flasher_ifnset(jlink)

board_runner_args(jlink "--device=MIMX8MN6_M7")
include(${ZEPHYR_BASE}/boards/common/jlink.board.cmake)
