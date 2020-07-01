/**
 * @file
 *
 * Neighbor discovery and stateless address autoconfiguration for IPv6.
 * Aims to be compliant with RFC 4861 (Neighbor discovery) and RFC 4862
 * (Address autoconfiguration).
 */

/*
 * Copyright (c) 2010 Inico Technologies Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Ivan Delamer <delamer@inicotech.com>
 *
 *
 * Please coordinate changes and requests with Ivan Delamer
 * <delamer@inicotech.com>
 */

#ifndef LWIP_HDR_ND6_H
#define LWIP_HDR_ND6_H

#include "lwip/opt.h"

#if LWIP_IPV6  /* don't build if not configured for use in lwipopts.h */

#include "lwip/ip6_addr.h"
#include "lwip/err.h"

#if defined (__cplusplus) && __cplusplus
extern "C" {
#endif


/** @cond liteos
 * 1 second period */
#define ND6_TMR_INTERVAL 1000

/** Router solicitations are sent in 4 second intervals (see RFC 4861, ch. 6.3.7)
 * @endcond */
#ifndef ND6_RTR_SOLICITATION_INTERVAL
#define ND6_RTR_SOLICITATION_INTERVAL  4000
#endif


#define ND6_SEND_FLAG_MULTICAST_DEST 0x01
#define ND6_SEND_FLAG_ALLNODES_DEST 0x02

#define ND6_SEND_FLAG_UNSPEC_SRC 0x10
#define SIZEOF_RDNSS_OPTION_BASE 8

/* Hop limit value */
#define ND6_HOPLIM 255

struct pbuf;
struct netif;
#ifdef LWIP_TESTBED
void nd6_remove_netif_neighbor_cache_entries(struct netif *netif);
#endif
void nd6_tmr(void);
void nd6_input(struct pbuf *p, struct netif *inp);
void nd6_clear_destination_cache(void);
struct netif *nd6_find_route(const ip6_addr_t *ip6addr);
err_t nd6_get_next_hop_addr_or_queue(struct netif *netif, struct pbuf *q, const ip6_addr_t *ip6addr, const u8_t **hwaddrp);
u16_t nd6_get_destination_mtu(const ip6_addr_t *ip6addr, struct netif *netif);
#if LWIP_ND6_TCP_REACHABILITY_HINTS
void nd6_reachability_hint(const ip6_addr_t *ip6addr);
#endif /* LWIP_ND6_TCP_REACHABILITY_HINTS */
void nd6_cleanup_netif(struct netif *netif);
#if LWIP_IPV6_MLD
void nd6_adjust_mld_membership(struct netif *netif, s8_t addr_idx, u8_t new_state);
#endif /* LWIP_IPV6_MLD */
void nd6_send_na(struct netif *netif, const ip6_addr_t *target_addr, u8_t flags);

#if LWIP_IPV6_SEND_ROUTER_SOLICIT
err_t nd6_send_rs(struct netif *netif);
#endif /* LWIP_IPV6_SEND_ROUTER_SOLICIT */

err_t nd6_add_neighbor_cache_entry(struct netif *netif, const ip6_addr_t *nbr_addr,
                                   const u8_t *addr, const u8_t addrlen);

const ip6_addr_t *nd6_get_prefix_addr(const ip6_addr_t *ip6addr, struct netif *netif);


#if defined(LWIP_RPL) && LWIP_RPL
void *nd6_add_default_router(const ip6_addr_t *router_addr, u32_t lifetime, struct netif *netif);

err_t nd6_get_default_router_ip(ip6_addr_t *router_addr, void *default_route);

void nd6_remove_default_router(void *default_route);

#endif

#if LWIP_IPV6_AUTOCONFIG
void nd6_clear_netif_autoconf_address(struct netif *netif);
#endif

int nd6_validate_options(u8_t *opt, int opt_len);
void nd6_restart_netif(struct netif *netif);
void nd6_report_groups(struct netif *netif, s8_t addr_idx);


#if defined (__cplusplus) && __cplusplus
}
#endif

#endif /* LWIP_IPV6 */

#endif /* LWIP_HDR_ND6_H */
