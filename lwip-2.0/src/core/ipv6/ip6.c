/**
 * @file
 *
 * IPv6 layer.
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

#include "lwip/opt.h"

#if LWIP_IPV6  /* don't build if not configured for use in lwipopts.h */

#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/netif.h"
#include "lwip/ip.h"
#include "lwip/ip6.h"
#include "lwip/ip6_addr.h"
#include "lwip/ip6_frag.h"
#include "lwip/icmp6.h"
#include "lwip/raw.h"
#include "lwip/udp.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/dhcp6.h"
#include "lwip/nd6.h"
#include "lwip/mld6.h"
#include "lwip/debug.h"
#include "lwip/stats.h"

#ifdef LWIP_HOOK_FILENAME
#include LWIP_HOOK_FILENAME
#endif

#if LWIP_IPV6_FILTER
/* This function is called when an ip packet received. The return value of this function will
 * decide accept or drop a ip packet when LWIP_IPV6_FILTER is Enabled and ip_filter function has been set
 */
LWIP_STATIC ip_filter_fn ip6_filter = NULL;
#endif /* LWIP_IPV6_FILTER*/

/**
 * Finds the appropriate network interface for a given IPv6 address. It tries to select
 * a netif following a sequence of heuristics:
 * 1) if there is only 1 netif, return it
 * 2) if the destination is a link-local address, try to match the src address to a netif.
 *    this is a tricky case because with multiple netifs, link-local addresses only have
 *    meaning within a particular subnet/link.
 * 3) tries to match the destination subnet to a configured address
 * 4) tries to find a router
 * 5) tries to match the source address to the netif
 * 6) returns the default netif, if configured
 *
 * @param src the source IPv6 address, if known
 * @param dest the destination IPv6 address for which to find the route
 * @return the netif on which to send to reach dest
 */
struct netif *
ip6_route(const ip6_addr_t *src, const ip6_addr_t *dest
#if LWIP_SO_DONTROUTE
  , rt_scope_t scope
#endif
)
{
  struct netif *netif = NULL;
  s8_t i;

#if !LWIP_SO_DONTROUTE
  /* If single netif configuration, fast return. */
  if ((netif_list != NULL) && (netif_list->next == NULL)) {
    if (!netif_is_up(netif_list) || !netif_is_link_up(netif_list)) {
      return NULL;
    }
    return netif_list;
  }
#endif

  /* Special processing for link-local addresses. */
  if (ip6_addr_islinklocal(dest)) {
    if (ip6_addr_isany(src)) {
      /* Use default netif, if Up. */
      if (netif_default == NULL || !netif_is_up(netif_default) ||
          !netif_is_link_up(netif_default)) {
        return NULL;
      }
      return netif_default;
    }

    /* Try to find the netif for the source address, checking that link is up. */
    for (netif = netif_list; netif != NULL; netif = netif->next) {
      if (!netif_is_up(netif) || !netif_is_link_up(netif)) {
        continue;
      }
      for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
        if (ip6_addr_isvalid(netif_ip6_addr_state(netif, i)) &&
            ip6_addr_cmp(src, netif_ip6_addr(netif, i))) {
          return netif;
        }
      }
    }

    /* netif not found, use default netif, if up */
    if (netif_default == NULL || !netif_is_up(netif_default) ||
        !netif_is_link_up(netif_default)) {
      return NULL;
    }
    return netif_default;
  }

#if LWIP_SO_DONTROUTE
    /* cross-network route entry should not been looked up if route-scope was link-only,
        currently only the default route entry was in this class */
  if (scope > RT_SCOPE_UNIVERSAL) {
    return NULL;
  }
#endif /* LWIP_SO_DONTROUTE */

  /* we come here for non-link-local addresses */
#ifdef LWIP_HOOK_IP6_ROUTE
  netif = LWIP_HOOK_IP6_ROUTE(src, dest);
  if (netif != NULL) {
    return netif;
  }
#endif

  /* See if the destination subnet matches a configured address. */
  for (netif = netif_list; netif != NULL; netif = netif->next) {
    if (!netif_is_up(netif) || !netif_is_link_up(netif)) {
      continue;
    }
    for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
      if (ip6_addr_isvalid(netif_ip6_addr_state(netif, i)) &&
          ip6_addr_netcmp(dest, netif_ip6_addr(netif, i))) {
        return netif;
      }
    }
  }

  /* Get the netif for a suitable router. */
  netif = nd6_find_route(dest);
  if ((netif != NULL) && netif_is_up(netif) && netif_is_link_up(netif)) {
    return netif;
  }

  /* try with the netif that matches the source address. */
  if (!ip6_addr_isany(src)) {
    for (netif = netif_list; netif != NULL; netif = netif->next) {
      if (!netif_is_up(netif) || !netif_is_link_up(netif)) {
        continue;
      }
      for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
        if (ip6_addr_isvalid(netif_ip6_addr_state(netif, i)) &&
            ip6_addr_cmp(src, netif_ip6_addr(netif, i))) {
          return netif;
        }
      }
    }
  }

#if LWIP_NETIF_LOOPBACK && !LWIP_HAVE_LOOPIF
  /* loopif is disabled, loopback traffic is passed through any netif */
  if (ip6_addr_isloopback(dest)) {
    /* don't check for link on loopback traffic */
    if (netif_default != NULL && netif_is_up(netif_default)) {
      return netif_default;
    }
    /* default netif is not up, just use any netif for loopback traffic */
    for (netif = netif_list; netif != NULL; netif = netif->next) {
      if (netif_is_up(netif)) {
        return netif;
      }
    }
    return NULL;
  }
#endif /* LWIP_NETIF_LOOPBACK && !LWIP_HAVE_LOOPIF */

  /* no matching netif found, use default netif, if up */
  if ((netif_default == NULL) || !netif_is_up(netif_default) || !netif_is_link_up(netif_default)) {
    return NULL;
  }
  return netif_default;
}

/**
 * @ingroup ip6
 * Select the best IPv6 source address for a given destination
 * IPv6 address. Loosely follows RFC 3484. "Strong host" behavior
 * is assumed.
 *
 * @param addr1 IPv6 Address 1
 * @param addr2 IPv6 Address 2
 * @param prefix_length Length of network prefix(in bits)
 * @return
 * Number of common prefix bits in addr1 & addr2 : On success
 * -1 : Invalid parameters
 */
int ip6_common_prefix_length(const ip6_addr_t *addr1, const ip6_addr_t *addr2, u8_t prefix_length)
{
  int common_prefix_length = 0;
  int i = 0;
  int bit_index;
  u8_t* addr1_char = NULL;
  u8_t* addr2_char = NULL;

  LWIP_ERROR("ip6_common_prefix_length: addr1 != NULL", (addr1 != NULL), return -1);
  LWIP_ERROR("ip6_common_prefix_length: addr2 != NULL", (addr2 != NULL), return -1);

  if ((prefix_length < 1) || (prefix_length > IP6_ADDR_LEN)) {
    LWIP_DEBUGF(IP6_DEBUG, ("ip6_common_prefix_length: Prefix length = %"X8_F": is invalid", prefix_length));
    return -1;
  }

  // Checking Word-By-Word
  while ((common_prefix_length < prefix_length) && (i < IP6_ADDR_U32_ARR_SIZE)) {
    if (addr1->addr[i] == addr2->addr[i]) {
      common_prefix_length += 32;  // u32_t occupy 32 bits
      ++i;
      continue;
    }
    break;
  }

  // If Already "prefix_length" number of bits are matched, then skip remaining part of the function
  if (common_prefix_length >= prefix_length) {
    goto exit;
  }

  // Checking Byte-By-Byte
  addr1_char = (u8_t *)(addr1);
  addr2_char = (u8_t *)(addr2);

  // Advancing i To Proper value so that it now indexes the next byte for comparison
  i *= 4;  // u32_t occupy 4 u8_t

  while ((common_prefix_length < prefix_length)) {
    if (addr1_char[i] == addr2_char[i]) {
      common_prefix_length += 8;  // u8_t occupy 8 bits
      ++i;
      continue;
    }
    break;
  }

  // If Already "prefix_length" number of bits are matched, then skip remaining part of the function
  if (common_prefix_length >= prefix_length) {
    goto exit;
  }

  // Checking Bit by Bit
  // bit_index is set to 7 so that the entire eight bits has to be checked
  bit_index = 7;

  // Checking whether the first nibble of the byte matches
  // This is done so as to reduce the number of bit-by-bit comparisons that may be done afterwards
  if ((u8_t)(addr1_char[i] >> 4) == (u8_t)(addr2_char[i] >> 4)) {
    common_prefix_length += 4;
    // bit_index is set to 3 so that only the last 4 bits has to be checked
    // (because the first 4 bits have already proved to be equal)
    bit_index = 3;
  }

  // If already "prefix_length" number of bits are matched, then skip remaining part of the function
  if (common_prefix_length >= prefix_length) {
    goto exit;
  }

  while (bit_index >= 0) {
    if ((u8_t)(addr1_char[i] >> (u32_t)bit_index) == (u8_t)(addr2_char[i] >> (u32_t)bit_index)) {
      ++common_prefix_length;
      --bit_index;
      continue;
    }
    break;
  }

exit:
  // Placing an upper bound so that the prefix length matched does not go beyond "prefix_length"
  common_prefix_length = LWIP_MIN(common_prefix_length, prefix_length);

  return common_prefix_length;
}


/*
 * @ingroup ip6
 * Select the best IPv6 source address for a given destination IPv6 address.
 *
 * This implementation follows RFC 6724 Sec. 5 to the following extent:
 * - Rules 1, 2, 3: fully implemented
 * - Rules 4, 5, 5.5: not applicable
 * - Rule 6: not implemented
 * - Rule 7: not applicable
 * - Rule 8: limited to addresses with /64 addresses
 *
 * For Rule 2, we deliberately deviate from RFC 6724 Sec. 3.1 by considering
 * ULAs to be of smaller scope than global addresses, to avoid that a preferred
 * ULA is picked over a deprecated global address when given a global address
 * as destination, as that would likely result in broken two-way communication.
 *
 * As long as temporary addresses are not supported (as used in Rule 7), a
 * proper implementation of Rule 8 would obviate the need to implement Rule 6.
 *
 * @param netif the netif on which to send a packet
 * @param dest the destination we are trying to reach (possibly not properly zoned)
 * @return the most suitable source address to use, or NULL if no suitable
 *         source address is found
 */
    /**
    @page RFC-6724 RFC-6724
    @par  RFC-6724 Section 5 Compliance Information
    @par Compliant Rules
    @par Rules which are compliant for Default Source Address Selection
     Rule 1 : Prefer same address\n
     Rule 2 : Prefer appropriate scope\n
     Rule 3 : Avoid deprecated addresses\n
     Rule 5 : Prefer outgoing interface.\n
     Rule 8 : Use longest matching prefix.\n
    @par Non-Compliant Rules
    @par Rules which are not compliant for Default Source Address Selection
    Rule 5.5 : Prefer addresses in a prefix advertised by the next-hop.\n
    @par Non-Applicable Rules
    @par Following rules are not currently applicable for lwIP stack.
    Rule 4   : Prefer home addresses.\n
     Rule 6   : Prefer matching label.\n
     Rule 7   : Prefer temporary addresses.\n
    @par Limitations
    Rule 8 supports prefix matching only upto 64 bits.
    */
const ip_addr_t*
ip6_select_source_address(struct netif *netif, const ip6_addr_t *dest)
{
  const ip_addr_t *best_addr = NULL;
  const ip6_addr_t *cand_addr = NULL;
  s8_t dest_scope, cand_scope;
  s8_t best_scope = IP6_MULTICAST_SCOPE_RESERVED;
  u8_t i, cand_pref;
  u8_t best_pref = 0;
  int best_bits = 0;
  u8_t prefix_length = 64;
  int cand_bits;

  /* Start by determining the scope of the given destination address. These
   * tests are hopefully (roughly) in order of likeliness to match. */
  if (ip6_addr_isglobal(dest)) {
    dest_scope = IP6_MULTICAST_SCOPE_GLOBAL;
  } else if (ip6_addr_islinklocal(dest) || ip6_addr_isloopback(dest)) {
    dest_scope = IP6_MULTICAST_SCOPE_LINK_LOCAL;
  } else if (ip6_addr_isuniquelocal(dest)) {
    dest_scope = IP6_MULTICAST_SCOPE_ORGANIZATION_LOCAL;
  } else if (ip6_addr_ismulticast(dest)) {
    dest_scope = ip6_addr_multicast_scope(dest);
  } else if (ip6_addr_issitelocal(dest)) {
    dest_scope = IP6_MULTICAST_SCOPE_SITE_LOCAL;
  } else {
    /* no match, treat as low-priority global scope */
    dest_scope = IP6_MULTICAST_SCOPE_RESERVEDF;
  }

  best_addr = NULL;

  for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
    /* Consider only valid (= preferred and deprecated) addresses. */
    if (!ip6_addr_isvalid(netif_ip6_addr_state(netif, i))) {
      continue;
    }

    cand_addr = netif_ip6_addr(netif, i);
    /* Rule 1 : If Destination Address is equal to the candidate address */
    if (ip6_addr_cmp(cand_addr, dest)) {
      return netif_ip_addr6(netif, i);
    }

    /* Determine the scope of this candidate address. Same ordering idea. */
    if (ip6_addr_isglobal(cand_addr)) {
      cand_scope = IP6_MULTICAST_SCOPE_GLOBAL;
    } else if (ip6_addr_islinklocal(cand_addr)) {
      cand_scope = IP6_MULTICAST_SCOPE_LINK_LOCAL;
    } else if (ip6_addr_isuniquelocal(cand_addr)) {
      cand_scope = IP6_MULTICAST_SCOPE_ORGANIZATION_LOCAL;
    } else if (ip6_addr_issitelocal(cand_addr)) {
      cand_scope = IP6_MULTICAST_SCOPE_SITE_LOCAL;
    } else {
      /* no match, treat as low-priority global scope */
      cand_scope = IP6_MULTICAST_SCOPE_RESERVEDF;
    }

    cand_pref = ip6_addr_ispreferred(netif_ip6_addr_state(netif, i));

    cand_bits = ip6_common_prefix_length(cand_addr, dest, prefix_length);
    if (cand_bits == -1) {
      cand_bits = 0;
    }

    if ((best_addr == NULL) ||                                      /* no alternative yet */
       ((cand_scope < best_scope) && (cand_scope >= dest_scope)) || /* Rule 2 : Prefer appropriate scope */
       ((cand_scope > best_scope) && (best_scope < dest_scope)) ||  /* Rule 2 : Prefer appropriate scope */
       ((cand_scope == best_scope) && ((cand_pref > best_pref) ||   /* Rule 3 : Avoid deprecated address */
       ((cand_pref == best_pref) && (cand_bits > best_bits))))) {   /* Rule 8 : Longest prefix matching address */
      /* We found a new "winning" candidate. */
      best_addr = netif_ip_addr6(netif, i);
      best_scope = cand_scope;
      best_pref = cand_pref;
      best_bits = cand_bits;
    }
  }

  return best_addr; /* may be NULL */
}

#if LWIP_IPV6_FORWARD
/**
 * Forwards an IPv6 packet. It finds an appropriate route for the
 * packet, decrements the HL value of the packet, and outputs
 * the packet on the appropriate interface.
 *
 * @param p the packet to forward (p->payload points to IP header)
 * @param iphdr the IPv6 header of the input packet
 * @param inp the netif on which this packet was received
 */
static void
ip6_forward(struct pbuf *p, struct ip6_hdr *iphdr, struct netif *inp)
{
  struct netif *netif = NULL;

  /* do not forward link-local or loopback addresses */
  if (ip6_addr_islinklocal(ip6_current_dest_addr()) ||
      ip6_addr_isloopback(ip6_current_dest_addr())) {
    LWIP_DEBUGF(IP6_DEBUG, ("ip6_forward: not forwarding link-local address.\n"));
    IP6_STATS_INC(ip6.rterr);
    IP6_STATS_INC(ip6.drop);
    return;
  }

  /* Find network interface where to forward this IP packet to. */
#if LWIP_SO_DONTROUTE
  netif = ip6_route(IP6_ADDR_ANY6, ip6_current_dest_addr(), RT_SCOPE_UNIVERSAL);
#else
  netif = ip6_route(IP6_ADDR_ANY6, ip6_current_dest_addr());
#endif /* LWIP_SO_DONTROUTE */
  if (netif == NULL) {
    LWIP_DEBUGF(IP6_DEBUG, ("ip6_forward: no route for %"X16_F":%"X16_F":%"X16_F":%"X16_F":%"X16_F":%"X16_F":%"X16_F":%"X16_F"\n",
        IP6_ADDR_BLOCK1(ip6_current_dest_addr()),
        IP6_ADDR_BLOCK2(ip6_current_dest_addr()),
        IP6_ADDR_BLOCK3(ip6_current_dest_addr()),
        IP6_ADDR_BLOCK4(ip6_current_dest_addr()),
        IP6_ADDR_BLOCK5(ip6_current_dest_addr()),
        IP6_ADDR_BLOCK6(ip6_current_dest_addr()),
        IP6_ADDR_BLOCK7(ip6_current_dest_addr()),
        IP6_ADDR_BLOCK8(ip6_current_dest_addr())));
#if LWIP_ICMP6
    /* Don't send ICMP messages in response to ICMP messages */
    if (IP6H_NEXTH(iphdr) != IP6_NEXTH_ICMP6) {
      icmp6_dest_unreach(p, ICMP6_DUR_NO_ROUTE);
    }
#endif /* LWIP_ICMP6 */
    IP6_STATS_INC(ip6.rterr);
    IP6_STATS_INC(ip6.drop);
    return;
  }
  /* Do not forward packets onto the same network interface on which
   * they arrived. */
  if (netif == inp) {
    LWIP_DEBUGF(IP6_DEBUG, ("ip6_forward: not bouncing packets back on incoming interface.\n"));
    IP6_STATS_INC(ip6.rterr);
    IP6_STATS_INC(ip6.drop);
    return;
  }

  /* decrement HL */
  if (IP6H_HOPLIM(iphdr)) {
      IP6H_HOPLIM_SET(iphdr, IP6H_HOPLIM(iphdr) - 1);
  }
  /* send ICMP6 if HL == 0 */
  if (IP6H_HOPLIM(iphdr) == 0) {
#if LWIP_ICMP6
    /* Don't send ICMP messages in response to ICMP messages */
    if (IP6H_NEXTH(iphdr) != IP6_NEXTH_ICMP6) {
      icmp6_time_exceeded(p, ICMP6_TE_HL);
    }
#endif /* LWIP_ICMP6 */
    IP6_STATS_INC(ip6.drop);
    return;
  }

  if (netif->mtu && (p->tot_len > netif->mtu)) {
#if LWIP_ICMP6
    /* Don't send ICMP messages in response to ICMP messages */
    if (IP6H_NEXTH(iphdr) != IP6_NEXTH_ICMP6) {
      icmp6_packet_too_big(p, netif->mtu);
    }
#endif /* LWIP_ICMP6 */
    IP6_STATS_INC(ip6.drop);
    return;
  }

  LWIP_DEBUGF(IP6_DEBUG, ("ip6_forward: forwarding packet to %"X16_F":%"X16_F":%"X16_F":%"X16_F":%"X16_F":%"X16_F":%"X16_F":%"X16_F"\n",
      IP6_ADDR_BLOCK1(ip6_current_dest_addr()),
      IP6_ADDR_BLOCK2(ip6_current_dest_addr()),
      IP6_ADDR_BLOCK3(ip6_current_dest_addr()),
      IP6_ADDR_BLOCK4(ip6_current_dest_addr()),
      IP6_ADDR_BLOCK5(ip6_current_dest_addr()),
      IP6_ADDR_BLOCK6(ip6_current_dest_addr()),
      IP6_ADDR_BLOCK7(ip6_current_dest_addr()),
      IP6_ADDR_BLOCK8(ip6_current_dest_addr())));

  /* transmit pbuf on chosen interface */
  netif->output_ip6(netif, p, ip6_current_dest_addr());
  IP6_STATS_INC(ip6.fw);
  IP6_STATS_INC(ip6.xmit);
  return;
}
#endif /* LWIP_IPV6_FORWARD */


/*
 * This function is called when there is extension options to be processed in destination header in IPV6 packet
 * @param p points to the pbuf buffer
 * @param dest_hdr points to the destination header in the IPV6
 * @param hlen header lenght of the destination option
 * @return need_ip6_input_cleanup = 1 means discard, 0 means continue process the packet
 */
void ip6_process_destination_header_extension_options(struct pbuf *p, struct ip6_dest_hdr *dest_hdr,
                                                      u16_t hlen, u8_t *need_ip6_input_cleanup)
{
  s32_t opt_offset;
  struct ip6_opt_hdr *opt_hdr = NULL;
  u32_t pointer_u32;

  *need_ip6_input_cleanup = 0;

  /* The extended option header starts right after Destination header. */
  opt_offset = IP6_DEST_HLEN;
  while (opt_offset < (s32_t)hlen) {
    s32_t opt_dlen = 0;
    u8_t clear_resource = 0;

    opt_hdr = (struct ip6_opt_hdr *)((u8_t *)dest_hdr + opt_offset);

    /*
     * @page RFC-2460 RFC-2460
     * @par  RFC-2460 Compliance Information
     * @par Compliant Section
     * IPv6 Extension Headers. Test v6LC.1.2.8: Option Processing, Destination Options Header
     * @par Behavior Description
     *
     * Our node conforms to RFC-2460. \n
     *  RFC-2460 does not support below extension options and the features corresponding to it. \n
     * @verbatim
     *   RFC-3775 --> IPV6 Mobility Support       - IP6_HOME_ADDRESS_OPTION (Option_Type = 201)
     *   RFC-2711 --> IPv6 Router Alert Option    - IP6_ROUTER_ALERT_OPTION (Option_Type = 5)
     *   RFC-2675 --> IPV6 Jumbo Payload Option   - IP6_JUMBO_OPTION        (Option_Type = 194)
     * @endverbatim
     * \n
     *   For these options and other extension header options, our node action conforms to RFC-2460: \n
     *   If the IPv6 node does not recognize the Option_Type, then the action it should take depends
     *   on the highest order two bits of the Option_Type.
     */
    switch (IP6_OPT_TYPE(opt_hdr)) {
      case IP6_PAD1_OPTION:
        /* PAD1 option deosn't have length and value field */
        opt_dlen = -1;
        break;

      case IP6_PADN_OPTION:
          if ((hlen - opt_offset) >= IP6_OPT_HLEN) { /* malformed packet */
            opt_dlen = IP6_OPT_DLEN(opt_hdr);
          } else {
            /* Discard the packet. */
            LWIP_DEBUGF(IP6_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                        ("ip6_input: malformed packet detected in PADN option rocessing, discarding it \n"));
            clear_resource = 1;
          }
        break;

      default:
        /* Check 2 MSB of Destination header type. */
        switch (IP6_OPT_TYPE_ACTION(opt_hdr)) {
          case 1:
            /* Discard the packet. */
            LWIP_DEBUGF(IP6_DEBUG,
                        ("ip6_input: packet with invalid destination option type dropped, \
                        highest order 2 bits value is 1\n"));
            clear_resource = 1;
            break;
          case 2:
            /* Send ICMP Parameter Problem */
            LWIP_DEBUGF(IP6_DEBUG,
                        ("ip6_input: packet with invalid destination option type dropped, \
                        highest order 2 bits value is 2\n"));
            pointer_u32 = (u32_t)((const u8_t *)opt_hdr - (const u8_t *)ip6_current_header());
            /* move payload pointer back to ip header */
            (void)pbuf_header_force(p, (s16_t)((u8_t*)p->payload - (const u8_t *)ip6_current_header()));
            icmp6_param_problem(p, ICMP6_PP_OPTION, pointer_u32);
            clear_resource = 1;
            break;
          case 3:
            /* Send ICMP Parameter Problem if destination address is not a multicast address */
            LWIP_DEBUGF(IP6_DEBUG,
                        ("ip6_input: packet with invalid destination option type dropped, \
                        highest order 2 bits value is 2\n"));
            if (!ip6_addr_ismulticast(ip6_current_dest_addr())) {
              pointer_u32 = (u32_t)((const u8_t *)opt_hdr - (const u8_t *)ip6_current_header());
              /* move payload pointer back to ip header */
              (void)pbuf_header_force(p, (s16_t)((u8_t*)p->payload - (const u8_t *)ip6_current_header()));
              icmp6_param_problem(p, ICMP6_PP_OPTION, pointer_u32);
            }
            clear_resource = 1;
            break;
            default:
              /* Skip over this option. */
              if ((hlen - opt_offset) >= IP6_OPT_HLEN) { /* malformed packet */
                opt_dlen = IP6_OPT_DLEN(opt_hdr);
              } else {
                /* Discard the packet. */
                LWIP_DEBUGF(IP6_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                            ("ip6_input: malformed packet detected in Unknown option processing, discarding it \n"));
                clear_resource = 1;
                break;
              }
              break;
          }
        break;
    }

    if (clear_resource) {
      (void)pbuf_free(p);
      IP6_STATS_INC(ip6.drop);
      *need_ip6_input_cleanup = 1;
      break;
    }
    /* Adjust the offset to move to the next extended option header */
    opt_offset = opt_offset + IP6_OPT_HLEN + opt_dlen;
  }

  return;
}

/*
 * This function is called by the network interface device driver when
 * an IPv6 packet is received. The function does the basic checks of the
 * IP header such as packet size being at least larger than the header
 * size etc. If the packet was not destined for us, the packet is
 * forwarded (using ip6_forward).
 *
 * Finally, the packet is sent to the upper layer protocol input function.
 *
 * @param p the received IPv6 packet (p->payload points to IPv6 header)
 * @param inp the netif on which this packet was received
 * @return ERR_OK if the packet was processed (could return ERR_* if it wasn't
 *         processed, but currently always returns ERR_OK)
 */
err_t
ip6_input(struct pbuf *p, struct netif *inp)
{
  struct ip6_hdr *ip6hdr = NULL;
  struct netif *netif = NULL;
  const u8_t *nexth = NULL;
  u16_t hlen; /* the current header length */
  u8_t i;
  s16_t proto;
#if LWIP_RAW

  u8_t raw_status;
  s8_t isCheckSumInvalid = 0;
#endif
  struct ip6_dest_hdr *dest_hdr = NULL;
  u8_t need_ip6_input_cleanup = 0;
  struct ip6_hdr *ip6hdrtmp = NULL;
  s32_t opt_offset;
  struct ip6_hbh_hdr *hbh_hdr = NULL;
  struct ip6_opt_hdr *opt_hdr = NULL;
  s32_t opt_dlen = 0;

  IP6_STATS_INC(ip6.recv);

#if LWIP_IPV6_FILTER
  if (ip6_filter != NULL && ip6_filter(p, inp) != ERR_OK) {
    (void)pbuf_free(p);
    IP6_STATS_INC(ip6.drop);
    return ERR_OK;
  }
#endif /* LWIP_IPV6_FILTER */

  if ((IP6_HLEN > p->len)) {
    LWIP_DEBUGF(IP6_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                ("IPv6 header (len %"U16_F") does not fit in first pbuf (len %"U16_F"), IP packet dropped.\n",
                (u16_t)IP6_HLEN, p->len));

    /* free (drop) packet pbufs */
    (void)pbuf_free(p);
    IP6_STATS_INC(ip6.lenerr);
    IP6_STATS_INC(ip6.drop);
    return ERR_OK;
  }

  /* identify the IP header */
  ip6hdr = (struct ip6_hdr *)p->payload;
  if (IP6H_V(ip6hdr) != 6) {
    LWIP_DEBUGF(IP6_DEBUG | LWIP_DBG_LEVEL_WARNING, ("IPv6 packet dropped due to bad version number %"U32_F"\n",
        IP6H_V(ip6hdr)));
    (void)pbuf_free(p);
    IP6_STATS_INC(ip6.err);
    IP6_STATS_INC(ip6.drop);
    return ERR_OK;
  }

#ifdef LWIP_HOOK_IP6_INPUT
  if (LWIP_HOOK_IP6_INPUT(p, inp)) {
    /* the packet has been eaten */
    return ERR_OK;
  }
#endif

  /* header length exceeds first pbuf length, or ip length exceeds total pbuf length? */
  if (((IP6H_PLEN(ip6hdr) + IP6_HLEN) > p->tot_len)) {
     LWIP_DEBUGF(IP6_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
        ("IPv6 (plen %"U16_F") is longer than pbuf (len %"U16_F"), IP packet dropped.\n",
            (u16_t)(IP6H_PLEN(ip6hdr) + IP6_HLEN), p->tot_len));

    /* free (drop) packet pbufs */
    (void)pbuf_free(p);
    IP6_STATS_INC(ip6.lenerr);
    IP6_STATS_INC(ip6.drop);
    return ERR_OK;
  }

  /* Trim pbuf. This should have been done at the netif layer,
   * but we'll do it anyway just to be sure that its done. */
  pbuf_realloc(p, (u16_t)(IP6_HLEN + IP6H_PLEN(ip6hdr)));

  /* copy IP addresses to aligned ip6_addr_t */
  ip_addr_copy_from_ip6(ip_data.current_iphdr_dest, ip6hdr->dest);
  ip_addr_copy_from_ip6(ip_data.current_iphdr_src, ip6hdr->src);

  /* Don't accept virtual IPv4 mapped IPv6 addresses.
   * Don't accept multicast source addresses. */
  if (ip6_addr_isipv4mappedipv6(ip_2_ip6(&ip_data.current_iphdr_dest)) ||
     ip6_addr_isipv4mappedipv6(ip_2_ip6(&ip_data.current_iphdr_src)) ||
     ip6_addr_ismulticast(ip_2_ip6(&ip_data.current_iphdr_src))) {
    /* free (drop) packet pbufs */
    (void)pbuf_free(p);
    IP6_STATS_INC(ip6.err);
    IP6_STATS_INC(ip6.drop);
    return ERR_OK;
  }

  /* current header pointer. */
  ip_data.current_ip6_header = ip6hdr;

  /* In netif, used in case we need to send ICMPv6 packets back. */
  ip_data.current_netif = inp;
  ip_data.current_input_netif = inp;

  /* match packet against an interface, i.e. is this packet for us? */
  if (ip6_addr_ismulticast(ip6_current_dest_addr())) {
    /* Always joined to multicast if-local and link-local all-nodes group. */
    if (ip6_addr_isallnodes_iflocal(ip6_current_dest_addr()) ||
        ip6_addr_isallnodes_linklocal(ip6_current_dest_addr())) {
      netif = inp;
    }
#if LWIP_IPV6_MLD
    else if (mld6_lookfor_group(inp, ip6_current_dest_addr())) {
      netif = inp;
    }
#else /* LWIP_IPV6_MLD */
    else if (ip6_addr_issolicitednode(ip6_current_dest_addr())) {
      /* Filter solicited node packets when MLD is not enabled
       * (for Neighbor discovery). */
      netif = NULL;
      for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
        if (!ip6_addr_isinvalid(netif_ip6_addr_state(inp, i)) &&
            ip6_addr_cmp_solicitednode(ip6_current_dest_addr(), netif_ip6_addr(inp, i))) {
          netif = inp;
          LWIP_DEBUGF(IP6_DEBUG, ("ip6_input: solicited node packet accepted on interface %c%c\n",
              netif->name[0], netif->name[1]));
          break;
        }
      }
    }
#endif /* LWIP_IPV6_MLD */
    else {
      netif = NULL;
    }
  } else {
    /* start trying with inp. if that's not acceptable, start walking the
       list of configured netifs.
       'first' is used as a boolean to mark whether we started walking the list */
    int first = 1;
    netif = inp;
    do {
      /* interface is up? */
      if (netif_is_up(netif)) {
        /* unicast to this interface address? address configured? */
        for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
          if (ip6_addr_isvalid(netif_ip6_addr_state(netif, i)) &&
              ip6_addr_cmp(ip6_current_dest_addr(), netif_ip6_addr(netif, i))) {
            /* exit outer loop */
            goto netif_found;
          }
        }
      }
      if (first) {
        if (ip6_addr_islinklocal(ip6_current_dest_addr())
#if !LWIP_NETIF_LOOPBACK || LWIP_HAVE_LOOPIF
            || ip6_addr_isloopback(ip6_current_dest_addr())
#endif /* !LWIP_NETIF_LOOPBACK || LWIP_HAVE_LOOPIF */
        ) {
          /* Do not match link-local addresses to other netifs. The loopback
           * address is to be considered link-local and packets to it should be
           * dropped on other interfaces, as per RFC 4291 Sec. 2.5.3. This
           * requirement cannot be implemented in the case that loopback
           * traffic is sent across a non-loopback interface, however.
           */
          netif = NULL;
          break;
        }
        first = 0;
        netif = netif_list;
      } else {
        netif = netif->next;
      }
      if (netif == inp) {
        netif = netif->next;
      }
    } while (netif != NULL);
netif_found:
    LWIP_DEBUGF(IP6_DEBUG, ("ip6_input: packet accepted on interface %c%c\n",
                netif ? netif->name[0] : 'X', netif ? netif->name[1] : 'X'));
  }

  /* "::" packet source address? (used in duplicate address detection) */
  if (ip6_addr_isany_val(*ip6_current_src_addr()) &&
      (!ip6_addr_issolicitednode(ip6_current_dest_addr()))) {
    /* packet source is not valid */
    /* free (drop) packet pbufs */
    LWIP_DEBUGF(IP6_DEBUG, ("ip6_input: packet with src ANY_ADDRESS dropped\n"));
    (void)pbuf_free(p);
    IP6_STATS_INC(ip6.drop);
    goto ip6_input_cleanup;
  }

  /* packet not for us? */
  if (netif == NULL) {
    /* packet not for us, route or discard */
    LWIP_DEBUGF(IP6_DEBUG | LWIP_DBG_TRACE, ("ip6_input: packet not for us.\n"));
#if LWIP_IPV6_FORWARD
    /* non-multicast packet? */
    if (!ip6_addr_ismulticast(ip6_current_dest_addr())) {
      /* try to forward IP packet on (other) interfaces */
      ip6_forward(p, ip6hdr, inp);
    }
#endif /* LWIP_IPV6_FORWARD */
    (void)pbuf_free(p);
    IP6_STATS_INC(ip6.drop);
    goto ip6_input_cleanup;
  }

  /* current netif pointer. */
  ip_data.current_netif = netif;

  /* Save next header type. */
  nexth = &IP6H_NEXTH(ip6hdr);

  /* Init header length. */
  hlen = ip_data.current_ip_header_tot_len = IP6_HLEN;

  /* Move to payload. */
  (void)pbuf_header(p, -IP6_HLEN);

  /* Process known option extension headers, if present. */
  while (*nexth != IP6_NEXTH_NONE) {
    switch (*nexth) {
      case IP6_NEXTH_HOPBYHOP:
        LWIP_DEBUGF(IP6_DEBUG, ("ip6_input: packet with Hop-by-Hop options header\n"));

        /* Get and check the header length, while staying in packet bounds. */
        hbh_hdr = (struct ip6_hbh_hdr *)p->payload;

        /* Get next header type. */
        nexth = (const u8_t *)p->payload;

        /*
         *@page RFC-2460 RFC-2460
         *@par Compliant Section
         *Section 4.  IPv6 Extension Headers. Test v6LC.1.2.1: Next Header Zero
         *@par Behavior Description
         *The lwIP stack will not send back the ICMP Parameter Problem message and discard
         *the packet when a packet has Next Header field of zero in a header other than an IPv6 header.
         *Also the processing of Hop-by-Hop Options is not performed.
         *The exception referred to in the preceding paragraph is the Hop-by-
         *Hop Options header, which carries information that must be examined
         *and processed by every node along a packet's delivery path, including
         *the source and destination nodes.  The Hop-by-Hop Options header,
         *when present, must immediately follow the IPv6 header.  Its presence
         *is indicated by the value zero in the Next Header field of the IPv6
         *header. \n
         *If, as a result of processing a header, a node is required to proceed
         *to the next header but the Next Header value in the current header is
         *unrecognized by the node, it should discard the packet and send an
         *ICMP Parameter Problem message to the source of the packet, with an
         *ICMP Code value of 1 ("unrecognized Next Header type encountered")
         *and the ICMP Pointer field containing the offset of the unrecognized
         *value within the original packet.  The same action should be taken if
         *a node encounters a Next Header value of zero in any header other \,
         *than an IPv6 header. \n
         *[RFC 8200 4. IPv6 Extension Headers] Modified the above behavior. By default no need to send
         *back the ICMP Parameter Problem message and discard the packet when a packet has Next
         *Header field of zero in a header other than an IPv6 header. Also the processing of Hop-by-Hop
         *Options header is changed from 'must' to 'may' by every node in the path \n
         * \n
         *NOTE: While RFC-2460 required that all nodes must examine and
         *process the Hop-by-Hop Options header, it is now expected that nodes
         *along a packet's delivery path only examine and process the
         *Hop-by-Hop Options header if explicitly configured to do so.
         */
        if (p->len < 2) {
          LWIP_DEBUGF(IP6_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
            ("IP6_NEXTH_HOPBYHOP: pbuf (len %"U16_F") is less than 2.\n", p->len));
          /* free (drop) packet pbufs */
          (void)pbuf_free(p);
          IP6_STATS_INC(ip6.lenerr);
          IP6_STATS_INC(ip6.drop);
          goto ip6_input_cleanup;
        }

        /* Get the header length. */
        hlen = (u16_t)(8 * (1 + *(u8_t *)((u8_t *)p->payload + 1)));

        ip_data.current_ip_header_tot_len = (u16_t)(ip_data.current_ip_header_tot_len + hlen);

        /* Skip over this header. */
        if (hlen > p->len) {
          LWIP_DEBUGF(IP6_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
            ("IPv6 options header (hlen %"U16_F") does not fit in first pbuf (len %"U16_F"), IPv6 packet dropped.\n",
              hlen, p->len));
          /* free (drop) packet pbufs */
          (void)pbuf_free(p);
          IP6_STATS_INC(ip6.lenerr);
          IP6_STATS_INC(ip6.drop);
          goto ip6_input_cleanup;
        }
        /* The extended option header starts right after Hop-by-Hop header. */
        opt_offset = IP6_HBH_HALFHLEN;
        while (opt_offset < (s32_t)hlen) {
          opt_hdr = (struct ip6_opt_hdr *)((u8_t *)hbh_hdr + opt_offset);

          switch (IP6_OPT_TYPE(opt_hdr)) {
            /* @todo: process IPV6 Hop-by-Hop option data */
            case IP6_PAD1_OPTION:
              /* PAD1 option doesn't have length and value field */
              opt_dlen = -1;
              break;
            case IP6_PADN_OPTION:
              opt_dlen = IP6_OPT_DLEN(opt_hdr);
              break;
            case IP6_ROUTER_ALERT_OPTION:
              opt_dlen = IP6_OPT_DLEN(opt_hdr);
              break;
            case IP6_JUMBO_OPTION:
              opt_dlen = IP6_OPT_DLEN(opt_hdr);
              break;
            default:
              /* Check 2 MSB of Hop-by-Hop header type. */
              switch (IP6_OPT_TYPE_ACTION(opt_hdr)) {
                case 1:
                  /* Discard the packet. */
                  LWIP_DEBUGF(IP6_DEBUG, ("ip6_input: packet with invalid Hop-by-Hop option type dropped.\n"));
                  (void)pbuf_free(p);
                  IP6_STATS_INC(ip6.drop);
                  goto ip6_input_cleanup;
                case 2:
                  /* Send ICMP Parameter Problem */
                  /* move payload pointer back to ip header */
                  (void)pbuf_header_force(p, (s16_t)((u8_t*)p->payload - (const u8_t *)ip6_current_header()));
                  icmp6_param_problem(p, ICMP6_PP_OPTION,
                                      (u32_t)((u8_t *)opt_hdr - (const u8_t *)ip6_current_header()));
                  LWIP_DEBUGF(IP6_DEBUG, ("ip6_input: packet with invalid Hop-by-Hop option type dropped.\n"));
                  (void)pbuf_free(p);
                  IP6_STATS_INC(ip6.drop);
                  goto ip6_input_cleanup;
                case 3:
                  /* Send ICMP Parameter Problem if destination address is not a multicast address */
                  if (!ip6_addr_ismulticast(ip6_current_dest_addr())) {
                    /* move payload pointer back to ip header */
                    (void)pbuf_header_force(p, (s16_t)((u8_t*)p->payload - (const u8_t *)ip6_current_header()));
                    icmp6_param_problem(p, ICMP6_PP_OPTION,
                                        (u32_t)((u8_t *)opt_hdr - (const u8_t *)ip6_current_header()));
                  }
                  LWIP_DEBUGF(IP6_DEBUG, ("ip6_input: packet with invalid Hop-by-Hop option type dropped.\n"));
                  (void)pbuf_free(p);
                  IP6_STATS_INC(ip6.drop);
                  goto ip6_input_cleanup;
                default:
                  /* Skip over this option. */
                  opt_dlen = IP6_OPT_DLEN(opt_hdr);
                  break;
              }
              break;
          }
          /* Adjust the offset to move to the next extended option header */
          opt_offset = opt_offset + IP6_OPT_HLEN + opt_dlen;
        }
        (void)pbuf_header(p, (s16_t)(-(s16_t)hlen));
        break;
      case IP6_NEXTH_DESTOPTS:
        LWIP_DEBUGF(IP6_DEBUG, ("ip6_input: packet with Destination options header\n"));

        /* Get next header type. */
        nexth = (const u8_t *)p->payload;
        dest_hdr = (struct ip6_dest_hdr *)p->payload;

        if (p->len < IP6_DEST_HLEN) {
          LWIP_DEBUGF(IP6_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
            ("IP6_NEXTH_DESTOPTS: pbuf (len %"U16_F") is less than 2.\n", p->len));
          /* free (drop) packet pbufs */
          (void)pbuf_free(p);
          IP6_STATS_INC(ip6.lenerr);
          IP6_STATS_INC(ip6.drop);
          goto ip6_input_cleanup;
        }

        /* Get the header length. */
        hlen = (u16_t)(8 * (1 + dest_hdr->_hlen));

        ip_data.current_ip_header_tot_len = (u16_t)(ip_data.current_ip_header_tot_len + hlen);

        /* Skip over this header. */
        if (hlen > p->len) {
          LWIP_DEBUGF(IP6_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
            ("IPv6 options header (hlen %"U16_F") does not fit in first pbuf (len %"U16_F"), IPv6 packet dropped.\n",
                hlen, p->len));
          /* free (drop) packet pbufs */
          (void)pbuf_free(p);
          IP6_STATS_INC(ip6.lenerr);
          IP6_STATS_INC(ip6.drop);
          goto ip6_input_cleanup;
        }

        /*
         *@page RFC-2460 RFC-2460
         *@par Compliant Section
         *Section 4.  IPv6 Extension Headers. Test v6LC.1.2.8: Option Processing, Destination Options Header
         *@par Behavior Description
         *Our code conforms to RFC-2460. \n
         *   RFC-2460 does not support the following extension options and the features corresponding to it. \n
         *@verbatim
         *   RFC-3775 --> IPV6 Mobility Support       - IP6_HOME_ADDRESS_OPTION (Option_Type = 201)
         *   RFC-2711 --> IPv6 Router Alert Option    - IP6_ROUTER_ALERT_OPTION (Option_Type = 5)
         *   RFC-2675 --> IPV6 Jumbo Payload Option   - IP6_JUMBO_OPTION        (Option Type = 194)
         *   @endverbatim
         *   For these options and other extension header options, our node action will conform to RFC-2460: \n
         *   If the IPv6 node does not recognize the Option_Type, then the action it should take depends
         *  on the highest order two bits of the Option_Type.
         */
        /* The extended option header starts right after Destination header. */
        ip6_process_destination_header_extension_options(p, dest_hdr, hlen, &need_ip6_input_cleanup);
        if (need_ip6_input_cleanup) {
          goto ip6_input_cleanup;
        }

        (void)pbuf_header(p, (s16_t)(-(s16_t)hlen));
        break;
      case IP6_NEXTH_ROUTING:
        LWIP_DEBUGF(IP6_DEBUG, ("ip6_input: packet with Routing header\n"));
        /* Get next header type. */
        nexth = (const u8_t *)p->payload;

        if (p->len < 2) {
          LWIP_DEBUGF(IP6_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
            ("IP6_NEXTH_ROUTING: pbuf (len %"U16_F") is less than 2.\n", p->len));
          /* free (drop) packet pbufs */
          (void)pbuf_free(p);
          IP6_STATS_INC(ip6.lenerr);
          IP6_STATS_INC(ip6.drop);
          goto ip6_input_cleanup;
        }
        /* Get the header length. */
        hlen = (u16_t)(8 * (1 + *((u8_t *)p->payload + 1)));
        ip_data.current_ip_header_tot_len = (u16_t)(ip_data.current_ip_header_tot_len + hlen);

        /* Skip over this header. */
        if (hlen > p->len) {
          LWIP_DEBUGF(IP6_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
            ("IPv6 options header (hlen %"U16_F") does not fit in first pbuf (len %"U16_F"), IPv6 packet dropped.\n",
              hlen, p->len));
          /* free (drop) packet pbufs */
          (void)pbuf_free(p);
          IP6_STATS_INC(ip6.lenerr);
          IP6_STATS_INC(ip6.drop);
          goto ip6_input_cleanup;
        }

        (void)pbuf_header(p, (s16_t)(-(s16_t)hlen));
        break;

      case IP6_NEXTH_FRAGMENT:
      {
        struct ip6_frag_hdr *frag_hdr;
        LWIP_DEBUGF(IP6_DEBUG, ("ip6_input: packet with Fragment header\n"));

        frag_hdr = (struct ip6_frag_hdr *)p->payload;

        if (p->len < 2) {
          LWIP_DEBUGF(IP6_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
            ("IP6_NEXTH_FRAGMENT:(pbuf len %"U16_F" is less than 2), IPv6 packet dropped.\n",
              p->len));
          /* free (drop) packet pbufs */
          (void)pbuf_free(p);
          IP6_STATS_INC(ip6.lenerr);
          IP6_STATS_INC(ip6.drop);
          goto ip6_input_cleanup;
        }

        /* Get next header type. */
        nexth = &frag_hdr->_nexth;

        /* Fragment Header length. */
        hlen = 8;
        ip_data.current_ip_header_tot_len = (u16_t)(ip_data.current_ip_header_tot_len + hlen);

        /* Make sure this header fits in current pbuf. */
        if (hlen > p->len) {
          LWIP_DEBUGF(IP6_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
            ("IPv6 options header (hlen %"U16_F") does not fit in first pbuf (len %"U16_F"), IPv6 packet dropped.\n",
                hlen, p->len));
          /* free (drop) packet pbufs */
          (void)pbuf_free(p);
          IP6_FRAG_STATS_INC(ip6_frag.lenerr);
          IP6_FRAG_STATS_INC(ip6_frag.drop);
          goto ip6_input_cleanup;
        }

        /* check payload length is multiple of 8 octets when mbit is set */
        if (IP6H_FRAG_MBIT(frag_hdr) && (IP6H_PLEN(ip6hdr) & 0x7)) {
          /* move payload pointer back to ip header */
          (void)pbuf_header_force(p, (s16_t)((u8_t*)p->payload - (const u8_t *)ip6_current_header()));
          /* ipv6 payload length is not multiple of 8 octets */
          icmp6_param_problem(p, ICMP6_PP_FIELD,
                              (u32_t)((u8_t*)(&ip6hdr->_plen) - (const u8_t *)ip6_current_header()));
          LWIP_DEBUGF(IP6_DEBUG, ("ip6_input: packet with invalid payload length dropped\n"));
          (void)pbuf_free(p);
          IP6_FRAG_STATS_INC(ip6_frag.lenerr);
          IP6_FRAG_STATS_INC(ip6_frag.drop);
          goto ip6_input_cleanup;
        }

        /* Offset == 0 and more_fragments == 0? */
        if ((frag_hdr->_fragment_offset &
             PP_HTONS(IP6_FRAG_OFFSET_MASK | IP6_FRAG_MORE_FLAG)) == 0) {
          /* This is a 1-fragment packet, usually a packet that we have
           * already reassembled. Skip this header anc continue.
           */
          (void)pbuf_header(p, (s16_t)(-(s16_t)hlen));
        } else {
#if LWIP_IPV6_REASS

          /* reassemble the packet */
          p = ip6_reass(p);
          /* packet not fully reassembled yet? */
          if (p == NULL) {
            goto ip6_input_cleanup;
          }

          /* Returned p point to IPv6 header.
           * Update all our variables and pointers and continue.
           */
          ip6hdr = (struct ip6_hdr *)p->payload;
          nexth = &IP6H_NEXTH(ip6hdr);
          hlen = IP6_HLEN;
          ip_data.current_ip_header_tot_len = IP6_HLEN;
          (void)pbuf_header(p, -IP6_HLEN);

#else /* LWIP_IPV6_REASS */
          /* free (drop) packet pbufs */
          LWIP_DEBUGF(IP6_DEBUG, ("ip6_input: packet with Fragment header dropped (with LWIP_IPV6_REASS==0)\n"));
          (void)pbuf_free(p);
          IP6_STATS_INC(ip6.opterr);
          IP6_STATS_INC(ip6.drop);
          goto ip6_input_cleanup;
#endif /* LWIP_IPV6_REASS */
        }
        break;
      }
      default:
        goto options_done;
    }

    if (*nexth == IP6_NEXTH_HOPBYHOP) {
      /* move payload pointer back to ip header */
      (void)pbuf_header_force(p, (s16_t)((u8_t*)p->payload - (const u8_t *)ip6_current_header()));
      /* Hop-by-Hop header comes only as a first option */
      icmp6_param_problem(p, ICMP6_PP_HEADER, (u32_t)(nexth - (const u8_t *)ip6_current_header()));
      LWIP_DEBUGF(IP6_DEBUG,
                  ("ip6_input: packet with Hop-by-Hop options header dropped (only valid as a first option)\n"));
      (void)pbuf_free(p);
      IP6_STATS_INC(ip6.opterr);
      IP6_STATS_INC(ip6.drop);
      goto ip6_input_cleanup;
    }
  }
options_done:

  /* p points to IPv6 header again. */
  (void)pbuf_header_force(p, (s16_t)ip_data.current_ip_header_tot_len);

  /* send to upper layers */
  LWIP_DEBUGF(IP6_DEBUG, ("ip6_input: \n"));
  ip6_debug_print(p);
  LWIP_DEBUGF(IP6_DEBUG, ("ip6_input: p->len %"U16_F" p->tot_len %"U16_F"\n", p->len, p->tot_len));

  ip6hdrtmp = (struct ip6_hdr *)p->payload;
  proto = IP6H_NEXTH(ip6hdrtmp);
  /* fragmentation data all merged will be given app */
  if (proto == IP6_NEXTH_FRAGMENT) {
    proto = *nexth;
  }

  (void)pbuf_header(p, (s16_t)(-(s16_t)ip_data.current_ip_header_tot_len));

  /* Successfully received bytes */
  STATS_INC_NUM(ip6.ip_rx_bytes, p->tot_len);
#if LWIP_RAW
  /*
   * @page RFC-2292 RFC-2292
   * @par Compliant Sections
   * Section 3. IPv6 Raw Sockets
   * Section 3.1. Checksums
   * Section 3.2. ICMPv6 Type Filtering
   * @par Behavior Description
   *      Support IPv6 raw sockets.
   *      Support IPv6 raw checksums.
   *      Support ICMPv6 Type Filtering.
   * @par Non-Compliant Section
   * Section 4. Ancillary Data
   * @par Behavior Description
   *      Ancillary data is not supported.
   */
  /* raw input did not eat the packet? */
  raw_status = raw_input6(p, proto, &isCheckSumInvalid);
  if (isCheckSumInvalid) {
    /* checksum validation is failed */
    /* It means packet is not given to application either due to checksum failure or some
     * or some other recv failure at the application side.
     */
    LWIP_DEBUGF(IP6_DEBUG, ("ip6_input:Failed in checksum validation proto = %"U16_F" \n", proto));
    (void)pbuf_free(p);
    IP6_STATS_INC(ip6.chkerr);
    IP6_STATS_INC(ip6.drop);
    goto ip6_input_cleanup;
  }

#endif /* LWIP_RAW */

  switch (*nexth) {
    case IP6_NEXTH_NONE:
      (void)pbuf_free(p);
      break;
#if LWIP_UDP
    case IP6_NEXTH_UDP:
#if LWIP_UDPLITE
    case IP6_NEXTH_UDPLITE:
#endif /* LWIP_UDPLITE */

      /* Point to payload. */
      udp_input(p, inp);

      break;
#endif /* LWIP_UDP */
#if LWIP_TCP
    case IP6_NEXTH_TCP:
      /* Point to payload. */
      tcp_input(p, inp);
      break;
#endif /* LWIP_TCP */
#if LWIP_ICMP6
    case IP6_NEXTH_ICMP6:
      /* Point to payload. */
      icmp6_input(p, inp);
      break;
#endif /* LWIP_ICMP */
    default:
      (void)pbuf_header(p, (s16_t)ip_data.current_ip_header_tot_len);
#if LWIP_ICMP6
    /* send ICMP parameter problem unless it was a multicast or ICMPv6 */
      if ((!ip6_addr_ismulticast(ip6_current_dest_addr())) &&
#if LWIP_RAW
        !raw_status &&
#endif
        (IP6H_NEXTH(ip6hdr) != IP6_NEXTH_ICMP6)) {
          /* problem is in extension headers i.e. extension next header is not valid */
          icmp6_param_problem(p, ICMP6_PP_HEADER, (u32_t)(nexth - (const u8_t *)ip6_current_header()));
      }
#endif /* LWIP_ICMP */
      LWIP_DEBUGF(IP6_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                  ("ip6_input: Unsupported transport protocol %"U16_F"\n", (u16_t)IP6H_NEXTH(ip6hdr)));
      (void)pbuf_free(p);
      IP6_STATS_INC(ip6.proterr);
      IP6_STATS_INC(ip6.drop);
      break;
  }

ip6_input_cleanup:
  ip_data.current_netif = NULL;
  ip_data.current_input_netif = NULL;
  ip_data.current_ip6_header = NULL;
  ip_data.current_ip_header_tot_len = 0;
  ip6_addr_set_zero(ip6_current_src_addr());
  ip6_addr_set_zero(ip6_current_dest_addr());

  return ERR_OK;
}


/**
 * Sends an IPv6 packet on a network interface. This function constructs
 * the IPv6 header. If the source IPv6 address is NULL, the IPv6 "ANY" address is
 * used as source (usually during network startup). If the source IPv6 address it
 * IP6_ADDR_ANY, the most appropriate IPv6 address of the outgoing network
 * interface is filled in as source address. If the destination IPv6 address is
 * LWIP_IP_HDRINCL, p is assumed to already include an IPv6 header and
 * p->payload points to it instead of the data.
 *
 * @param p the packet to send (p->payload points to the data, e.g. next
            protocol header; if dest == LWIP_IP_HDRINCL, p already includes an
            IPv6 header and p->payload points to that IPv6 header)
 * @param src the source IPv6 address to send from (if src == IP6_ADDR_ANY, an
 *         IP address of the netif is selected and used as source address.
 *         if src == NULL, IP6_ADDR_ANY is used as source)
 * @param dest the destination IPv6 address to send the packet to
 * @param hl the Hop Limit value to be set in the IPv6 header
 * @param tc the Traffic Class value to be set in the IPv6 header
 * @param nexth the Next Header to be set in the IPv6 header
 * @param netif the netif on which to send this packet
 * @return ERR_OK if the packet was sent OK
 *         ERR_BUF if p doesn't have enough space for IPv6/LINK headers
 *         returns errors returned by netif->output
 */
err_t
ip6_output_if(struct pbuf *p, const ip6_addr_t *src, const ip6_addr_t *dest,
             u8_t hl, u8_t tc,
             u8_t nexth, struct netif *netif)
{
  const ip6_addr_t *src_used = src;
  if (dest != LWIP_IP_HDRINCL) {
    if (src != NULL && ip6_addr_isany(src)) {
      src_used = ip_2_ip6(ip6_select_source_address(netif, dest));
      if ((src_used == NULL) || ip6_addr_isany(src_used)) {
        /* No appropriate source address was found for this packet. */
        LWIP_DEBUGF(IP6_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("ip6_output: No suitable source address for packet.\n"));
        IP6_STATS_INC(ip6.rterr);
        return ERR_RTE;
      }
    }
  }
  return ip6_output_if_src(p, src_used, dest, hl, tc, nexth, netif);
}

/**
 * Same as ip6_output_if() but 'src' address is not replaced by netif address
 * when it is 'any'.
 */
err_t
ip6_output_if_src(struct pbuf *p, const ip6_addr_t *src, const ip6_addr_t *dest,
             u8_t hl, u8_t tc,
             u8_t nexth, struct netif *netif)
{
  struct ip6_hdr *ip6hdr = NULL;
  ip6_addr_t dest_addr;

  LWIP_IP_CHECK_PBUF_REF_COUNT_FOR_TX(p);

  /* Should the IPv6 header be generated or is it already included in p? */
  if (dest != LWIP_IP_HDRINCL) {
    /* generate IPv6 header */
    if (pbuf_header(p, IP6_HLEN)) {
      LWIP_DEBUGF(IP6_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("ip6_output: not enough room for IPv6 header in pbuf\n"));
      IP6_STATS_INC(ip6.err);
      return ERR_BUF;
    }

    ip6hdr = (struct ip6_hdr *)p->payload;
    LWIP_ASSERT("check that first pbuf can hold struct ip6_hdr",
                (p->len >= sizeof(struct ip6_hdr)));

    IP6H_HOPLIM_SET(ip6hdr, hl);
    IP6H_NEXTH_SET(ip6hdr, nexth);

    /* dest cannot be NULL here */
    ip6_addr_copy(ip6hdr->dest, *dest);

    IP6H_VTCFL_SET(ip6hdr, 6, tc, 0);
    IP6H_PLEN_SET(ip6hdr, (u16_t)(p->tot_len - IP6_HLEN));

    if (src == NULL) {
      src = IP6_ADDR_ANY6;
    }
    /* src cannot be NULL here */
    ip6_addr_copy(ip6hdr->src, *src);

  } else {
    /* IP header already included in p */
    ip6hdr = (struct ip6_hdr *)p->payload;
    ip6_addr_copy(dest_addr, ip6hdr->dest);
    dest = &dest_addr;
  }

  IP6_STATS_INC(ip6.xmit);
  STATS_INC_NUM(ip6.ip_tx_bytes, p->tot_len);

  LWIP_DEBUGF(IP6_DEBUG, ("ip6_output_if: %c%c%"U16_F"\n", netif->name[0], netif->name[1], (u16_t)netif->num));
  ip6_debug_print(p);

#if ENABLE_LOOPBACK
  {
    int i;
#if !LWIP_HAVE_LOOPIF
    if (ip6_addr_isloopback(dest)) {
      return netif_loop_output(netif, p);
    }
#endif /* !LWIP_HAVE_LOOPIF */
    for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
      if (ip6_addr_isvalid(netif_ip6_addr_state(netif, i)) &&
          ip6_addr_cmp(dest, netif_ip6_addr(netif, i))) {
        /* Packet to self, enqueue it for loopback */
        LWIP_DEBUGF(IP6_DEBUG, ("netif_loop_output()\n"));
        return netif_loop_output(netif, p);
      }
    }
  }
#if LWIP_MULTICAST_TX_OPTIONS
  if ((p->flags & PBUF_FLAG_MCASTLOOP) != 0) {
    (void)netif_loop_output(netif, p);
  }
#endif /* LWIP_MULTICAST_TX_OPTIONS */
#endif /* ENABLE_LOOPBACK */
#if LWIP_IPV6_FRAG
  /* don't fragment if interface has mtu set to 0 [loopif] */
  if (netif_mtu6(netif) && (p->tot_len > nd6_get_destination_mtu(dest, netif))) {
    return ip6_frag(p, netif, dest);
  }
#endif /* LWIP_IPV6_FRAG */

  LWIP_DEBUGF(IP6_DEBUG, ("netif->output_ip6()\n"));
  return netif->output_ip6(netif, p, dest);
}

/**
 * Simple interface to ip6_output_if. It finds the outgoing network
 * interface and calls upon ip6_output_if to do the actual work.
 *
 * @param p the packet to send (p->payload points to the data, e.g. next
            protocol header; if dest == LWIP_IP_HDRINCL, p already includes an
            IPv6 header and p->payload points to that IPv6 header)
 * @param src the source IPv6 address to send from (if src == IP6_ADDR_ANY, an
 *         IP address of the netif is selected and used as source address.
 *         if src == NULL, IP6_ADDR_ANY is used as source)
 * @param dest the destination IPv6 address to send the packet to
 * @param hl the Hop Limit value to be set in the IPv6 header
 * @param tc the Traffic Class value to be set in the IPv6 header
 * @param nexth the Next Header to be set in the IPv6 header
 *
 * @return ERR_RTE if no route is found
 *         see ip_output_if() for more return values
 */
err_t
ip6_output(struct pbuf *p, const ip6_addr_t *src, const ip6_addr_t *dest,
          u8_t hl, u8_t tc, u8_t nexth, struct ip_pcb *pcb)
{
  struct netif *netif = NULL;
  struct ip6_hdr *ip6hdr = NULL;
  ip6_addr_t src_addr, dest_addr;
#if !LWIP_SO_DONTROUTE && !LWIP_SO_BINDTODEVICE
    LWIP_UNUSED_ARG(pcb);
#endif
#if LWIP_SO_DONTROUTE
  rt_scope_t scope = RT_SCOPE_UNIVERSAL;
#endif /* LWIP_SO_DONTROUTE */

  LWIP_IP_CHECK_PBUF_REF_COUNT_FOR_TX(p);

  IP6_ADDR(&dest_addr, 0, 0, 0, 0);

#if LWIP_SO_DONTROUTE
    if ((pcb != NULL) && ip_get_option(pcb, SOF_DONTROUTE)) {
      p->flags |= PBUF_FLAG_IS_LINK_ONLY;
      scope = RT_SCOPE_LINK;
    }
#endif /* LWIP_SO_DONTROUTE */
    /* find the outgoing network interface for this packet,
    * first check if this socket already bind to one specific netif,
    * if not, then do regular route lookup
    */
#if LWIP_SO_BINDTODEVICE
    if ((pcb != NULL) && (pcb->ifindex != 0)) {
      netif = netif_find_by_ifindex(pcb->ifindex);
    }
    else
#endif
    {
      if (dest != LWIP_IP_HDRINCL) {
#if LWIP_SO_DONTROUTE
        netif = ip6_route(src, dest, scope);
#else
        netif = ip6_route(src, dest);
#endif
      } else {
        /* IP header included in p, read addresses. */
        ip6hdr = (struct ip6_hdr *)p->payload;
        ip6_addr_copy(src_addr, ip6hdr->src);
        ip6_addr_copy(dest_addr, ip6hdr->dest);
#if LWIP_SO_DONTROUTE
        netif = ip6_route(&src_addr, &dest_addr, scope);
#else
        netif = ip6_route(&src_addr, &dest_addr);
#endif
      }
    }
  if (netif == NULL) {
      LWIP_DEBUGF(IP6_DEBUG, ("ip6_output: no route for %"X16_F":%"X16_F":%"X16_F":%"X16_F":%"X16_F":%"X16_F":%"X16_F":%"X16_F"\n",
        IP6_ADDR_BLOCK1(dest ? dest : &dest_addr),
        IP6_ADDR_BLOCK2(dest ? dest : &dest_addr),
        IP6_ADDR_BLOCK3(dest ? dest : &dest_addr),
        IP6_ADDR_BLOCK4(dest ? dest : &dest_addr),
        IP6_ADDR_BLOCK5(dest ? dest : &dest_addr),
        IP6_ADDR_BLOCK6(dest ? dest : &dest_addr),
        IP6_ADDR_BLOCK7(dest ? dest : &dest_addr),
        IP6_ADDR_BLOCK8(dest ? dest : &dest_addr)));
    IP6_STATS_INC(ip6.rterr);
    return ERR_RTE;
  }

  return ip6_output_if(p, src, dest, hl, tc, nexth, netif);
}


#if LWIP_NETIF_HWADDRHINT
/** Like ip6_output, but takes and addr_hint pointer that is passed on to netif->addr_hint
 *  before calling ip6_output_if.
 *
 * @param p the packet to send (p->payload points to the data, e.g. next
            protocol header; if dest == LWIP_IP_HDRINCL, p already includes an
            IPv6 header and p->payload points to that IPv6 header)
 * @param src the source IPv6 address to send from (if src == IP6_ADDR_ANY, an
 *         IP address of the netif is selected and used as source address.
 *         if src == NULL, IP6_ADDR_ANY is used as source)
 * @param dest the destination IPv6 address to send the packet to
 * @param hl the Hop Limit value to be set in the IPv6 header
 * @param tc the Traffic Class value to be set in the IPv6 header
 * @param nexth the Next Header to be set in the IPv6 header
 * @param addr_hint address hint pointer set to netif->addr_hint before
 *        calling ip_output_if()
 *
 * @return ERR_RTE if no route is found
 *         see ip_output_if() for more return values
 */
err_t
ip6_output_hinted(struct pbuf *p, const ip6_addr_t *src, const ip6_addr_t *dest,
          u8_t hl, u8_t tc, u8_t nexth, u8_t *addr_hint)
{
  struct netif *netif = NULL;
  struct ip6_hdr *ip6hdr = NULL;
  ip6_addr_t src_addr, dest_addr;
  err_t err;

  LWIP_IP_CHECK_PBUF_REF_COUNT_FOR_TX(p);

  if (dest != LWIP_IP_HDRINCL) {
#if LWIP_SO_DONTROUTE
    netif = ip6_route(src, dest, RT_SCOPE_UNIVERSAL);
#else
    netif = ip6_route(src, dest);
#endif
  } else {
    /* IP header included in p, read addresses. */
    ip6hdr = (struct ip6_hdr *)p->payload;
    ip6_addr_copy(src_addr, ip6hdr->src);
    ip6_addr_copy(dest_addr, ip6hdr->dest);
#if LWIP_SO_DONTROUTE
    netif = ip6_route(&src_addr, &dest_addr, RT_SCOPE_UNIVERSAL);
#else
    netif = ip6_route(&src_addr, &dest_addr);
#endif
  }

  if (netif == NULL) {
    LWIP_DEBUGF(IP6_DEBUG, ("ip6_output: no route for %"X16_F":%"X16_F":%"X16_F":%"X16_F":%"X16_F":%"X16_F":%"X16_F":%"X16_F"\n",
        IP6_ADDR_BLOCK1(dest),
        IP6_ADDR_BLOCK2(dest),
        IP6_ADDR_BLOCK3(dest),
        IP6_ADDR_BLOCK4(dest),
        IP6_ADDR_BLOCK5(dest),
        IP6_ADDR_BLOCK6(dest),
        IP6_ADDR_BLOCK7(dest),
        IP6_ADDR_BLOCK8(dest)));
    IP6_STATS_INC(ip6.rterr);
    return ERR_RTE;
  }

  NETIF_SET_HWADDRHINT(netif, addr_hint);
  err = ip6_output_if(p, src, dest, hl, tc, nexth, netif);
  NETIF_SET_HWADDRHINT(netif, NULL);

  return err;
}
#endif /* LWIP_NETIF_HWADDRHINT*/

#if LWIP_IPV6_MLD
/**
 * Add a hop-by-hop options header with a router alert option and padding.
 *
 * Used by MLD when sending a Multicast listener report/done message.
 *
 * @param p the packet to which we will prepend the options header
 * @param nexth the next header protocol number (e.g. IP6_NEXTH_ICMP6)
 * @param value the value of the router alert option data (e.g. IP6_ROUTER_ALERT_VALUE_MLD)
 * @return ERR_OK if hop-by-hop header was added, ERR_* otherwise
 */
err_t
ip6_options_add_hbh_ra(struct pbuf *p, u8_t nexth, u8_t value)
{
  struct ip6_hbh_hdr *hbh_hdr = NULL;

  /* Move pointer to make room for hop-by-hop options header. */
  if (pbuf_header(p, sizeof(struct ip6_hbh_hdr))) {
    LWIP_DEBUGF(IP6_DEBUG, ("ip6_options: no space for options header\n"));
    IP6_STATS_INC(ip6.err);
    return ERR_BUF;
  }

  hbh_hdr = (struct ip6_hbh_hdr *)p->payload;

  /* Set fields. */
  hbh_hdr->_nexth = nexth;
  hbh_hdr->_hlen = 0;
  hbh_hdr->_ra_opt_type = IP6_ROUTER_ALERT_OPTION;
  hbh_hdr->_ra_opt_dlen = 2;
  hbh_hdr->_ra_opt_data = value;
  hbh_hdr->_padn_opt_type = IP6_PADN_ALERT_OPTION;
  hbh_hdr->_padn_opt_dlen = 0;

  return ERR_OK;
}
#endif /* LWIP_IPV6_MLD */

#if LWIP_IPV6_FILTER
/*
 * Set ip filter for input packet.
 */
err_t set_ip6_filter(ip_filter_fn filter_fn)
{
    ip6_filter = filter_fn;
    return ERR_OK;
}
#endif /* LWIP_IPV6_FILTER */

#if IP6_DEBUG
/* Print an IPv6 header by using LWIP_DEBUGF
 * @param p an IPv6 packet, p->payload pointing to the IPv6 header
 */
void
ip6_debug_print(struct pbuf *p)
{
  struct ip6_hdr *ip6hdr = (struct ip6_hdr *)p->payload;

  LWIP_DEBUGF(IP6_DEBUG, ("IPv6 header:\n"));
  LWIP_DEBUGF(IP6_DEBUG, ("+-------------------------------+\n"));
  LWIP_DEBUGF(IP6_DEBUG, ("| %2"U16_F" |  %3"U16_F"  |      %7"U32_F"     | (ver, class, flow)\n",
                    IP6H_V(ip6hdr),
                    IP6H_TC(ip6hdr),
                    IP6H_FL(ip6hdr)));
  LWIP_DEBUGF(IP6_DEBUG, ("+-------------------------------+\n"));
  LWIP_DEBUGF(IP6_DEBUG, ("|     %5"U16_F"     |  %3"U16_F"  |  %3"U16_F"  | (plen, nexth, hopl)\n",
                    IP6H_PLEN(ip6hdr),
                    IP6H_NEXTH(ip6hdr),
                    IP6H_HOPLIM(ip6hdr)));
  LWIP_DEBUGF(IP6_DEBUG, ("+-------------------------------+\n"));
  LWIP_DEBUGF(IP6_DEBUG, ("|  %4"X32_F" |  %4"X32_F" |  %4"X32_F" |  %4"X32_F" | (src)\n",
                    IP6_ADDR_BLOCK1(&(ip6hdr->src)),
                    IP6_ADDR_BLOCK2(&(ip6hdr->src)),
                    IP6_ADDR_BLOCK3(&(ip6hdr->src)),
                    IP6_ADDR_BLOCK4(&(ip6hdr->src))));
  LWIP_DEBUGF(IP6_DEBUG, ("|  %4"X32_F" |  %4"X32_F" |  %4"X32_F" |  %4"X32_F" |\n",
                    IP6_ADDR_BLOCK5(&(ip6hdr->src)),
                    IP6_ADDR_BLOCK6(&(ip6hdr->src)),
                    IP6_ADDR_BLOCK7(&(ip6hdr->src)),
                    IP6_ADDR_BLOCK8(&(ip6hdr->src))));
  LWIP_DEBUGF(IP6_DEBUG, ("+-------------------------------+\n"));
  LWIP_DEBUGF(IP6_DEBUG, ("|  %4"X32_F" |  %4"X32_F" |  %4"X32_F" |  %4"X32_F" | (dest)\n",
                    IP6_ADDR_BLOCK1(&(ip6hdr->dest)),
                    IP6_ADDR_BLOCK2(&(ip6hdr->dest)),
                    IP6_ADDR_BLOCK3(&(ip6hdr->dest)),
                    IP6_ADDR_BLOCK4(&(ip6hdr->dest))));
  LWIP_DEBUGF(IP6_DEBUG, ("|  %4"X32_F" |  %4"X32_F" |  %4"X32_F" |  %4"X32_F" |\n",
                    IP6_ADDR_BLOCK5(&(ip6hdr->dest)),
                    IP6_ADDR_BLOCK6(&(ip6hdr->dest)),
                    IP6_ADDR_BLOCK7(&(ip6hdr->dest)),
                    IP6_ADDR_BLOCK8(&(ip6hdr->dest))));
  LWIP_DEBUGF(IP6_DEBUG, ("+-------------------------------+\n"));

  if (IP6H_NEXTH(ip6hdr) == IP6_NEXTH_ICMP6) {
    struct icmpv6_hdr *icmp6hdr;
    (void)pbuf_header(p, (s16_t)(-(s16_t)IP6_HLEN));
    icmp6hdr = (struct icmpv6_hdr *)p->payload;
    LWIP_DEBUGF(IP6_DEBUG, ("|     %8"U16_F"     |  %8"U16_F"  | (ICMPv6-Type, ICMPv6-Code)\n",
                    icmp6hdr->type,
                    icmp6hdr->code));
    (void)pbuf_header(p, (s16_t)((s16_t)IP6_HLEN));
    LWIP_DEBUGF(IP6_DEBUG, ("+-------------------------------+\n"));
  }
}
#endif /* IP6_DEBUG */

#endif /* LWIP_IPV6 */
