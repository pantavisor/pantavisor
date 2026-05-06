/*
 * Copyright (c) 2026 Pantacor Ltd.
 * SPDX-License-Identifier: MIT
 */
#ifndef PVX_SERVICES_NFT_H
#define PVX_SERVICES_NFT_H

#include "include/xconnect.h"

// Bring up / tear down the inet pvx_services nft table (or iptables fallback).
int pvx_services_nft_init(void);
void pvx_services_nft_teardown(void);

// Install / remove the DNAT rule for one Tier-1 link. Idempotent: stale
// rules for the same (consumer,name) are removed first.
int pvx_services_nft_add_dnat(const struct pvx_link *link);
int pvx_services_nft_del_dnat(const struct pvx_link *link);

#endif
