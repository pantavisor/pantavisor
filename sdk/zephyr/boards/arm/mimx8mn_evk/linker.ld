/*
 * Copyright (c) 2024-2026 Pantacor Ltd.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * i.MX8M Nano M7 — DDR region at 0x7E000000 (16 MiB reserved by Linux).
 */

#include <zephyr/devicetree.h>

MEMORY
     {
        DDR      (wx) : ORIGIN = 0x7e000000, LENGTH = 0x01000000
     }

#include <zephyr/arch/arm/cortex_m/scripts/linker.ld>
