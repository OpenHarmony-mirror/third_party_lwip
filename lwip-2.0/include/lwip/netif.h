/**
 * @file
 * netif API (to be used from TCPIP thread)
 */

/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
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
 * Author: Adam Dunkels <adam@sics.se>
 *
 */
#ifndef LWIP_HDR_NETIF_H
#define LWIP_HDR_NETIF_H

#include "lwip/opt.h"

#define ENABLE_LOOPBACK (LWIP_NETIF_LOOPBACK || LWIP_HAVE_LOOPIF)

#include "lwip/nd6.h"
#include "lwip/err.h"

#include "lwip/ip_addr.h"

#include "lwip/def.h"
#include "lwip/pbuf.h"
#include "lwip/stats.h"
#include "netif/etharp.h"
#include "netif/driverif.h"
#include "arch/sys_arch.h"
#include "lwip/if.h"

#if LWIP_NETIF_PROMISC
#include "lwip/sys.h"
#endif

#if defined (__cplusplus) && __cplusplus
extern "C" {
#endif

/* Throughout this file, IP addresses are expected to be in
 * the same byte order as in IP_PCB. */

/** @cond liteosnetif
    The maximum of all used hardware address lengths
    across all types of interfaces in use.
    This does not have to be changed, normally. */
#ifndef NETIF_MAX_HWADDR_LEN
#define NETIF_MAX_HWADDR_LEN 6U
#endif

/**
 * @defgroup netif_flags Flags
 * @ingroup netif
 * @{
 */

/** Defines whether the network interface is 'up'. This is
 * a software flag used to control whether this network
 * interface is enabled and processes traffic.
 * It must be set by the startup code before this netif can be used
 * (also for dhcp/autoip).
 */
#define NETIF_FLAG_UP           0x01U
/** If set, the netif has broadcast capability.
 * Set by the netif driver in its init function. */
#define NETIF_FLAG_BROADCAST    0x02U
/** If set, the interface has an active link
 *  (set by the network interface driver).
 * Either set by the netif driver in its init function (if the link
 * is up at that time) or at a later point when the link comes up
 * (if link detection is supported by the hardware). */
#define NETIF_FLAG_LINK_UP      0x04U
/** If set, the netif is an ethernet device using ARP.
 * Set by the netif driver in its init function.
 * Used to check input packet types and use of DHCP. */
#define NETIF_FLAG_ETHARP       0x08U
/** If set, the netif is an ethernet device. It might not use
 * ARP or TCP/IP if it is used for PPPoE only.
 */
#define NETIF_FLAG_ETHERNET     0x10U
/** If set, the netif has IGMP capability.
 * Set by the netif driver in its init function. */
#define NETIF_FLAG_IGMP         0x20U
/** If set, the netif has MLD6 capability.
 * Set by the netif driver in its init function. */
#define NETIF_FLAG_MLD6         0x40U

/** If set, the interface is configured using DHCP.
 * Set by the DHCP code when starting or stopping DHCP. */
#define NETIF_FLAG_DHCP         0x80U

#if DRIVER_STATUS_CHECK
/** If set, the netif has send capability.
 * Set by the netif driver when its is ready to send. */
#define NETIF_FLAG_DRIVER_RDY   0x100U
#endif
/** If set, the netif is one end of a point-to-point connection.
 * Set by the netif driver in its init function. */
#define NETIF_FLAG_POINTTOPOINT 0x200U

#if LWIP_TX_CSUM_OFFLOAD
/* If set, the netif has checksum offload capability, Set by the netif driver */
#define NETIF_FLAG_DRIVER_CSUM_SUPPORT   0x400U
#endif

#define NETIF_FLAG_LOOPBACK 0x800


#if LWIP_NETIF_PROMISC
#define NETIF_FLAG_PROMISC 0x1000U
#define NETIF_FLAG_PROMISC_RUNNING 0x2000U
#endif  /* LWIP_NETIF_PROMISC */
/**
 * @}
 */

enum lwip_internal_netif_client_data_index {
#if LWIP_IPV4
#if LWIP_DHCP
  LWIP_NETIF_CLIENT_DATA_INDEX_DHCP,
#endif
#if LWIP_AUTOIP
  LWIP_NETIF_CLIENT_DATA_INDEX_AUTOIP,
#endif
#if LWIP_IGMP
  LWIP_NETIF_CLIENT_DATA_INDEX_IGMP,
#endif
#endif /* LWIP_IPV4 */
#if LWIP_IPV6
#if LWIP_IPV6_DHCP6
  LWIP_NETIF_CLIENT_DATA_INDEX_DHCP6,
#endif
#if LWIP_IPV6_MLD
  LWIP_NETIF_CLIENT_DATA_INDEX_MLD6,
#endif /* LWIP_IPV6_MLD */
#endif /* LWIP_IPV6 */
  LWIP_NETIF_CLIENT_DATA_INDEX_MAX
};

#if LWIP_CHECKSUM_CTRL_PER_NETIF
#define NETIF_CHECKSUM_GEN_IP       0x0001
#define NETIF_CHECKSUM_GEN_UDP      0x0002
#define NETIF_CHECKSUM_GEN_TCP      0x0004
#define NETIF_CHECKSUM_GEN_ICMP     0x0008
#define NETIF_CHECKSUM_GEN_ICMP6    0x0010
#define NETIF_CHECKSUM_CHECK_IP     0x0100
#define NETIF_CHECKSUM_CHECK_UDP    0x0200
#define NETIF_CHECKSUM_CHECK_TCP    0x0400
#define NETIF_CHECKSUM_CHECK_ICMP   0x0800
#define NETIF_CHECKSUM_CHECK_ICMP6  0x1000
#define NETIF_CHECKSUM_ENABLE_ALL   0xFFFF
#define NETIF_CHECKSUM_DISABLE_ALL  0x0000
#endif /* LWIP_CHECKSUM_CTRL_PER_NETIF */

struct netif;

/** MAC Filter Actions, these are passed to a netif's igmp_mac_filter or
 * mld_mac_filter callback function. */
enum netif_mac_filter_action {
  /** Delete a filter entry */
  NETIF_DEL_MAC_FILTER = 0,
  /** Add a filter entry */
  NETIF_ADD_MAC_FILTER = 1
};

s8_t netif_find_dst_ip6addr_mac_addr(ip_addr_t *ipaddr, ip_addr_t **dst_addr, struct eth_addr **eth_ret);
/** Function prototype for netif init functions. Set up flags and output/linkoutput
 * callback functions in this function.
 *
 * @param netif Indicates the netif to initialize.
 */
typedef err_t (*netif_init_fn)(struct netif *netif);
/** Function prototype for netif->input functions. This function is saved as 'input'
 * callback function in the netif struct. Call this function when a packet has been received.
 * Note-
 * Passing a pbuf chain to ethernet_input (src/netif/ethernet.c) will not work as the function assumes the
   packet is stored in one pbuf
 * (for example, checks (p->len <= SIZEOF_ETH_HDR) instead of comparing p->tot_len, and assuming that the
   next header offsets are on the same pbuf.
 *
 * @param p Indicates the received packet, copied into a pbuf.
 * @param inp Indicates the netif which received the packet.
 */
typedef err_t (*netif_input_fn)(struct pbuf *p, struct netif *inp);

#if LWIP_IPV4
/** Function prototype for netif->output functions. Called by lwIP when a packet
 * is sent. For ethernet netif, set this to 'etharp_output' and set
 * 'linkoutput'.
 *
 * @param netif Indicates the netif which sends a packet.
 * @param p Indicates the packet to send (p->payload points to IP header)
 * @param ipaddr Indicates the IP address to which the packet is sent.
 */
typedef err_t (*netif_output_fn)(struct netif *netif, struct pbuf *p,
       const ip4_addr_t *ipaddr);
#endif /* LWIP_IPV4*/

#if LWIP_IPV6
/** Function prototype for netif->output_ip6 functions. Called by lwIP when a packet
 * shall be sent. For ethernet netif, set this to 'ethip6_output' and set
 * 'linkoutput'.
 *
 * @param netif The netif which shall send a packet
 * @param p The packet to send (p->payload points to IP header)
 * @param ipaddr The IPv6 address to which the packet shall be sent
 */
typedef err_t (*netif_output_ip6_fn)(struct netif *netif, struct pbuf *p,
       const ip6_addr_t *ipaddr);
#endif /* LWIP_IPV6 */

/** Function prototype for netif->linkoutput functions. Only used for ethernet
 * netifs. This function is called by ARP when a packet shall be sent.
 *
 * @param netif The netif which shall send a packet
 * @param p The packet to send (raw ethernet packet)
 */
typedef err_t (*netif_linkoutput_fn)(struct netif *netif, struct pbuf *p);
/* Function prototype for netif status- or link-callback functions. */
/**
* @ingroup Threadsafe_Network_Interfaces
* @par Description
* Netif status callback.
*/
typedef void (*netif_status_callback_fn)(struct netif *netif);
#if LWIP_IPV4 && LWIP_IGMP
/** Function prototype for netif igmp_mac_filter functions */
typedef err_t (*netif_igmp_mac_filter_fn)(struct netif *netif,
       const ip4_addr_t *group, enum netif_mac_filter_action action);
#endif /* LWIP_IPV4 && LWIP_IGMP */
#if LWIP_IPV6 && LWIP_IPV6_MLD
/** Function prototype for netif mld_mac_filter functions */
typedef err_t (*netif_mld_mac_filter_fn)(struct netif *netif,
       const ip6_addr_t *group, enum netif_mac_filter_action action);
#endif /* LWIP_IPV6 && LWIP_IPV6_MLD */

#if LWIP_DHCP || LWIP_AUTOIP || LWIP_IGMP || LWIP_IPV6_MLD || (LWIP_NUM_NETIF_CLIENT_DATA > 0)
u8_t netif_alloc_client_data_id(void);
/** @ingroup netif_cd
 * Set client data. Obtain ID from netif_alloc_client_data_id().
 */
#define netif_set_client_data(netif, id, data) netif_get_client_data(netif, id) = (data)
/** @ingroup netif_cd
 * Get client data. Obtain ID from netif_alloc_client_data_id().
 */
#define netif_get_client_data(netif, id)       (netif)->client_data[(id)]
#endif /* LWIP_DHCP || LWIP_AUTOIP || (LWIP_NUM_NETIF_CLIENT_DATA > 0) */

#ifndef IFNAMSIZ
/* Length of interface name.  */
#define IFNAMSIZ  16
#endif

#if LWIP_IPV6
/**
* @ingroup Duplicate_Address_Callback
* @brief
*   This callback is invoked when duplicate addresses are available in the
*   system, default behavior is to stop using those addresses.
*
*   @param[in] netif       Indicates pointer to the pre-allocated netif structure on
*                                   which duplicate addr has occured.
*   @param[in] ipaddr    Indicates duplicate IP6 address.
*   @param[in] state     Indicates current state of duplicate Ip6 address.
*
*   @returns
*     void
*   @note
*   prototype void (*lwip_duplicate_addr_handler_callback)(struct netif *, ip6_addr_t , u8_t );
*/


/*A callback prototype for handling duplicate address.*/
typedef void (*lwip_ipv6_addr_event)(struct netif *, ip6_addr_t, u8_t);

#define LWIP_IPV6_ND6_FLAG_DAD 0x01U
#define LWIP_IPV6_ND6_FLAG_DEPRECATED 0x02U

#if (defined(LWIP_IPV6_DUP_DETECT_ATTEMPTS) && LWIP_IPV6_DUP_DETECT_ATTEMPTS)
#define LWIP_IS_DAD_ENABLED(netif) (((netif)->ipv6_flags & LWIP_IPV6_ND6_FLAG_DAD))
#else
#define LWIP_IS_DAD_ENABLED(netif) 0
#endif
#endif /* LWIP_IPV6*/

/** Generic data structure used for all lwIP network interfaces.
 *  The following fields should be filled in by the initialization
 *  function for the device driver: hwaddr_len, hwaddr[], mtu, flags */
struct netif {
  /** Indicates a pointer to next in linked list. */
  struct netif *next;

#if LWIP_RPL
  int isnode_br;
#endif

#if LWIP_IPV4
  /** IP address configuration in network byte order */
  ip_addr_t ip_addr;  /**< Indicates the IP address configuration in network byte order. */
  ip_addr_t netmask;  /**< Indicates the netmask for the IP. */
  ip_addr_t gw;       /**< Indicates the gateway. */

#endif /* LWIP_IPV4 */
#if LWIP_IPV6
  /** Array of IPv6 addresses for this netif. */
  ip_addr_t ip6_addr[LWIP_IPV6_NUM_ADDRESSES];
  /** The state of each IPv6 address (Tentative, Preferred, etc).
   * @see ip6_addr.h */
  u8_t ip6_addr_state[LWIP_IPV6_NUM_ADDRESSES];
#if LWIP_IPV6_ADDRESS_LIFETIMES
  /** Remaining valid and preferred lifetime of each IPv6 address, in seconds.
   * For valid lifetimes, the special value of IP6_ADDR_LIFE_STATIC (0)
   * indicates the address is static and has no lifetimes. */
  u32_t ip6_addr_valid_life[LWIP_IPV6_NUM_ADDRESSES];
  u32_t ip6_addr_pref_life[LWIP_IPV6_NUM_ADDRESSES];
#endif /* LWIP_IPV6_ADDRESS_LIFETIMES */
#endif /* LWIP_IPV6 */
  /** This function is called by the network device driver
   *  to pass a packet up the TCP/IP stack. */
  netif_input_fn input;
#if LWIP_IPV4
  /** This function is called by the IP module when it wants
   *  to send a packet on the interface. This function typically
   *  first resolves the hardware address, then sends the packet.
   *  For ethernet physical layer, this is usually etharp_output() */
  netif_output_fn output;
#endif /* LWIP_IPV4 */
  /** This function is called by ethernet_output() when it wants
   *  to send a packet on the interface. This function outputs
   *  the pbuf as-is on the link medium. */
  netif_linkoutput_fn linkoutput;
#if LWIP_IPV6
  /** This function is called by the IPv6 module when it wants
   *  to send a packet on the interface. This function typically
   *  first resolves the hardware address, then sends the packet.
   *  For ethernet physical layer, this is usually ethip6_output() */
  netif_output_ip6_fn output_ip6;
#endif /* LWIP_IPV6 */
#if LWIP_NETIF_STATUS_CALLBACK
  /** This function is called when the netif state is set to up or down
   */
  netif_status_callback_fn status_callback;  /**< Called when the netif state is set to up or down. */
#endif /* LWIP_NETIF_STATUS_CALLBACK */
#if LWIP_NETIF_LINK_CALLBACK
  /** This function is called when the netif link is set to up or down
   */
  netif_status_callback_fn link_callback;  /**< Called when the netif link is set to up or down. */
#endif /* LWIP_NETIF_LINK_CALLBACK */
#if LWIP_NETIF_REMOVE_CALLBACK
  /** This function is called when the netif has been removed */
  netif_status_callback_fn remove_callback;  /**< Called when the netif is removed.  */
#endif /* LWIP_NETIF_REMOVE_CALLBACK */
  /** This field can be set by the device driver and could point
   *  to state information for the device. */
  void *state;      /**< This field can be set by the device driver and could point to state information
  for the device.*/
  /* This function is called by lwIP to send a packet on the interface.*/
  drv_send_fn drv_send;  /**< This function is called when lwIP wants to send a packet to interface. */
  /* This function is called by lwIP
   *  to set the mac_address of the interface.*/
  drv_set_hwaddr_fn drv_set_hwaddr;  /**<  This function is called when lwIP wants to set the mac_address
  of the interface.*/
#if LWIP_NETIF_ETHTOOL
  struct ethtool_ops *ethtool_ops;
#endif
#if LWIP_DHCPS
  /* DHCP Server Informarion for this netif */
  struct dhcps *dhcps;
#endif
#if LWIP_NETIF_PROMISC
  /** This function is called by  lwIP
   *  to set/unset the promiscuous mode of the interface.*/
  drv_config_fn drv_config;
#endif /*LWIP_NETIF_PROMISC*/
#ifdef netif_get_client_data
  void* client_data[LWIP_NETIF_CLIENT_DATA_INDEX_MAX + LWIP_NUM_NETIF_CLIENT_DATA];
#endif
#if LWIP_IPV6_AUTOCONFIG
  /** Indicates whether this netif is enabled for IPv6 autoconfiguration. */
  u8_t ip6_autoconfig_enabled;
#endif /* LWIP_IPV6_AUTOCONFIG */
#if LWIP_IPV6_SEND_ROUTER_SOLICIT
  /** Number of Router Solicitation messages that remain to be sent. */
  u8_t rs_count;
#endif /* LWIP_IPV6_SEND_ROUTER_SOLICIT */
#if LWIP_NETIF_HOSTNAME
  /* the hostname buffer for this netif. */
  char hostname[NETIF_HOSTNAME_MAX_LEN];
#endif /* LWIP_NETIF_HOSTNAME */
#if LWIP_CHECKSUM_CTRL_PER_NETIF
  u16_t chksum_flags;
#endif /* LWIP_CHECKSUM_CTRL_PER_NETIF*/
  /** maximum transfer unit (in bytes) */
  u16_t mtu;     /**< Maximum transfer unit (in bytes). */
#if LWIP_IPV6 && LWIP_ND6_ALLOW_RA_UPDATES
  /** maximum transfer unit (in bytes), updated by RA */
  u16_t mtu6;
#endif /* LWIP_IPV6 && LWIP_ND6_ALLOW_RA_UPDATES */
  /** number of bytes used in hwaddr */
  u8_t hwaddr_len;   /**< Number of bytes used in hwaddr. \n */
  /* Indicates the link level hardware address of this interface. */
  u8_t hwaddr[NETIF_MAX_HWADDR_LEN];   /**<  Indicates the link level hardware address
  of this interface.*/
  /* link layer type, ethernet or wifi */
  u16_t link_layer_type;   /**< Indicates whether the link layer type is ethernet or wifi. */
  /* flags (see NETIF_FLAG_ above) */
  u32_t flags;  /**< Indicates flags (see NETIF_FLAG_ above). */

#if LWIP_NETIF_PROMISC
  atomic_t flags_ext;
  u32_t flags_ext1;
#endif /* LWIP_NETIF_PROMISC */
  /** descriptive abbreviation */
  char name[IFNAMSIZ];  /**< Descriptive abbreviation. */
  /** number of this interface */
  u8_t num;    /**< Indicates the number of this interface. */
#if MIB2_STATS
  /** link type (from "snmp_ifType" enum from snmp_mib2.h) */
  u8_t link_type;  /**< Indicates the Link type (from "snmp_ifType" enum from snmp.h). */
  /** (estimate) link speed */
  u32_t link_speed;   /**< Indicates the (estimate) Link speed. */
  /** timestamp at last change made (up/down) */
  u32_t ts;  /**< Indicates the timestamp at last change made (up/down). */
  /** counters */
  struct stats_mib2_netif_ctrs mib2_counters; /**< Indicates counters. */
#endif /* MIB2_STATS */
#if LWIP_IPV4 && LWIP_IGMP
  /** This function could be called to add or delete an entry in the multicast
      filter table of the ethernet MAC. */
  netif_igmp_mac_filter_fn igmp_mac_filter; /**< This function must be called to add or delete a
  entry in the multicast filter table of the ethernet MAC. */
#endif /* LWIP_IPV4 && LWIP_IGMP */
#if LWIP_IPV6 && LWIP_IPV6_MLD
  /** This function must be called to add or delete an entry in the IPv6 multicast
      filter table of the ethernet MAC. */
  netif_mld_mac_filter_fn mld_mac_filter;
#endif /* LWIP_IPV6 && LWIP_IPV6_MLD */
#if LWIP_NETIF_HWADDRHINT
  u8_t *addr_hint;  /**< Indicates the hardware type hint. */
#endif /* LWIP_NETIF_HWADDRHINT */
#if ENABLE_LOOPBACK
  /* List of packets to be queued for ourselves. */
  struct pbuf *loop_first; /**< Indicates the list of packets to be queued for ourselves. */
  struct pbuf *loop_last; /**< Indicates the list of packets to be queued for ourselves. */
#if LWIP_LOOPBACK_MAX_PBUFS
  u16_t loop_cnt_current;  /**< Indicates the pbuf count. */
#endif /* LWIP_LOOPBACK_MAX_PBUFS */
#endif /* ENABLE_LOOPBACK */
  u8_t ifindex; /* Interface Index mapped to each netif. Starts from 1 */

#if DRIVER_STATUS_CHECK
  s32_t waketime; /**< Started when netif_stop_queue is called from driver. */
#endif

#if LWIP_IPV6
  /** Call back needs to be registered if adaptor requires notification for IPv6 DAD */
  lwip_ipv6_addr_event  ipv6_addr_event_cb;
  u8_t ipv6_flags;
#endif
};

#if LWIP_CHECKSUM_CTRL_PER_NETIF
#define NETIF_SET_CHECKSUM_CTRL(netif, chksumflags) do { \
  (netif)->chksum_flags = chksumflags; } while(0)
#define IF__NETIF_CHECKSUM_ENABLED(netif, chksumflag) if (((netif) == NULL) || (((netif)->chksum_flags & (chksumflag)) != 0))
#else /* LWIP_CHECKSUM_CTRL_PER_NETIF */
#define NETIF_SET_CHECKSUM_CTRL(netif, chksumflags)
#define IF__NETIF_CHECKSUM_ENABLED(netif, chksumflag)
#endif /* LWIP_CHECKSUM_CTRL_PER_NETIF */

#if LWIP_SINGLE_NETIF
#define NETIF_FOREACH(netif) if (((netif) = netif_default) != NULL)
#else /* LWIP_SINGLE_NETIF */
/** The list of network interfaces. */
extern struct netif *netif_list;
#define NETIF_FOREACH(netif) for ((netif) = netif_list; (netif) != NULL; (netif) = (netif)->next)
#endif /* LWIP_SINGLE_NETIF */
/** The default network interface. */
extern struct netif *netif_default;
s8_t  netif_find_dst_ipaddr(ip_addr_t *ipaddr, ip_addr_t **dst_addr);
void netif_init(void);

#if LWIP_DHCP
err_t netif_dhcp_off(struct netif *netif);
#endif

u8_t netif_check_num_isusing(const char* ifname, const u8_t num);

#if LWIP_IPV4
struct netif *netif_add(struct netif *netif, const ip4_addr_t *ipaddr,
                        const ip4_addr_t *netmask, const ip4_addr_t *gw);
#else
struct netif *netif_add(struct netif *netif);
#endif

#if LWIP_IPV4
err_t netif_set_addr(struct netif *netif, const ip4_addr_t *ipaddr, const ip4_addr_t *netmask,
                     const ip4_addr_t *gw);

err_t
netif_get_addr(struct netif *netif, ip4_addr_t *ipaddr, ip4_addr_t *netmask, ip4_addr_t *gw);

#endif /* LWIP_IPV4 */
#ifdef LWIP_TESTBED
err_t netif_reset(struct netif *netif);
#endif
err_t netif_remove(struct netif *netif);

/* Returns a network interface given its name. The name is of the form
   "et0", where the first two letters are the "name" field in the
   netif structure, and the digit is in the num field in the same
   structure. */
struct netif *netif_find(const char *name);

struct netif *netif_find_by_ipaddr(const ip_addr_t *ipaddr);

struct netif *netif_find_by_ifindex(u8_t ifindex);

u8_t netif_ipaddr_isbrdcast(const ip_addr_t *ipaddr);


err_t netif_set_default(struct netif *netif);

#if LWIP_IPV4
void netif_set_ipaddr(struct netif *netif, const ip4_addr_t *ipaddr);
void netif_set_netmask(struct netif *netif, const ip4_addr_t *netmask);
void netif_set_gw(struct netif *netif, const ip4_addr_t *gw);
struct netif *netif_find_by_ip4addr(const ip_addr_t *ipaddr);
/** @ingroup netif_ip4 */
#define netif_ip4_addr(netif)    ((const ip4_addr_t*)ip_2_ip4(&((netif)->ip_addr)))
/** @ingroup netif_ip4 */
#define netif_ip4_netmask(netif) ((const ip4_addr_t*)ip_2_ip4(&((netif)->netmask)))
/** @ingroup netif_ip4 */
#define netif_ip4_gw(netif)      ((const ip4_addr_t*)ip_2_ip4(&((netif)->gw)))
/** @ingroup netif_ip4 */
#define netif_ip_addr4(netif)    ((const ip_addr_t*)&((netif)->ip_addr))
/** @ingroup netif_ip4 */
#define netif_ip_netmask4(netif) ((const ip_addr_t*)&((netif)->netmask))
/** @ingroup netif_ip4 */
#define netif_ip_gw4(netif)      ((const ip_addr_t*)&((netif)->gw))
#endif /* LWIP_IPV4 */

err_t netif_set_up(struct netif *netif);
err_t netif_set_down(struct netif *netif);
err_t netif_set_mtu(struct netif *netif, u16_t netif_mtu);
err_t netif_set_hwaddr(struct netif *netif, const unsigned char *hw_addr, int hw_len);

void
netif_get_hwaddr(struct netif *netif, unsigned char *hw_addr, int hw_len);
/** @ingroup netif
 * Ask if an interface is up
 */
#define netif_is_up(netif) (((netif)->flags & NETIF_FLAG_UP) ? (u8_t)1 : (u8_t)0)

#if LWIP_NETIF_STATUS_CALLBACK
/* Sets the callback to call when the interface is brought up/down. */
void netif_set_status_callback(struct netif *netif, netif_status_callback_fn status_callback);
#endif /* LWIP_NETIF_STATUS_CALLBACK */
#if LWIP_NETIF_REMOVE_CALLBACK

/**
* @ingroup  Driver_Interfaces
* @brief
*   Sets the callback to call when the interface is removed.
*
* @param[in]   netif                               Indicates the netif structure.
* @param[in]   netif_status_callback_fn    Indicates the netif set status callback function.
*/

void netif_set_remove_callback(struct netif *netif, netif_status_callback_fn remove_callback);
#endif /* LWIP_NETIF_REMOVE_CALLBACK */

err_t netif_set_link_up(struct netif *netif);
err_t netif_set_link_down(struct netif *netif);
/** Ask if a link is up */
#define netif_is_link_up(netif) (((netif)->flags & NETIF_FLAG_LINK_UP) ? (u8_t)1 : (u8_t)0)

#if LWIP_NETIF_PROMISC
void netif_update_promiscuous_mode_status(struct netif *netif, u8_t set);
void netif_start_promisc_mode(u8_t ifindex);
void netif_stop_promisc_mode(u8_t ifindex);
#endif  /* LWIP_NETIF_PROMISC */

#if DRIVER_STATUS_CHECK
err_t
netif_wake_queue(struct netif *netif);
err_t
netif_stop_queue(struct netif *netif);
#endif

#if DRIVER_STATUS_CHECK
/** Ask if a driver is ready to send */
#define netif_is_ready(netif) (((netif)->flags & NETIF_FLAG_DRIVER_RDY) ? (u8_t)1 : (u8_t)0)
#endif


#if LWIP_NETIF_LINK_CALLBACK
err_t netif_set_link_callback(struct netif *netif, netif_status_callback_fn link_callback);
#endif /* LWIP_NETIF_LINK_CALLBACK */

#if LWIP_NETIF_HOSTNAME
/** @ingroup netif */
#define netif_set_hostname(netif, name) do { if((netif) != NULL) { (netif)->hostname = name; }}while(0)
/** @ingroup netif */
#define netif_get_hostname(netif) (((netif) != NULL) ? ((netif)->hostname) : NULL)
#endif /* LWIP_NETIF_HOSTNAME */

#if LWIP_IGMP
/** @ingroup netif */
/**
*
* Macro to set the IGMP mac filter function.
* The macro should be used after enabling LWIP_IPV4 and LWIP_IGMP
* The netif igmp_mac_filter function must be called to add or delete an ipv4 entry in the multicast filter
  table of the ethernet MAC.
* The macro is not thread safe , and the set macro should be called immediately after netif_add.
* This macro cannot be called in runtime.
*/
#define netif_set_igmp_mac_filter(netif, function) do { if((netif) != NULL) { (netif)->igmp_mac_filter = function; }}while(0)
/**
* Macro to get the IGMP mac filter function .
* The macro should be used after enabling LWIP_IPV4 and LWIP_IGMP
* The netif igmp_mac_filter function must be called to add or delete an ipv4 entry in the multicast filter
  table of the ethernet MAC.
* The macro is not thread safe , and the get macro should be called immediately after netif_add.
*/
#define netif_get_igmp_mac_filter(netif) (((netif) != NULL) ? ((netif)->igmp_mac_filter) : NULL)
#endif /* LWIP_IGMP */

#if LWIP_IPV6 && LWIP_IPV6_MLD
/** @ingroup netif */
/**
* Macro to set the MLD6 mac filter function
* The macro should be used after enabling LWIP_IPV6 and LWIP_IPV6_MLD
* netif mld_mac_filter filter function must be called to add or delete an ipv6 entry in the multicast filter
  table of the ethernet MAC.
* The macro is not thread safe , and the set macro should be called immediately after netif_add.
* This macro cannot be called in runtime.
*/

#define netif_set_mld_mac_filter(netif, function) do { if((netif) != NULL) { (netif)->mld_mac_filter = function; }}while(0)
/**
* Macro to get the MLD6 mac filter function
* The macro should be used after enabling LWIP_IPV6 and LWIP_IPV6_MLD
* netif mld_mac_filter filter function must be called to add or delete an ipv6 entry in the multicast filter
  table of the ethernet MAC.
* The macro is not thread safe , and the get macro should be called immediately after netif_add.
*/
#define netif_get_mld_mac_filter(netif) (((netif) != NULL) ? ((netif)->mld_mac_filter) : NULL)
/**
* Macro to access the mld_mac_filter function added through the the netif_set_mld_mac_filter.
* The macro should be used after enabling LWIP_IPV6 and LWIP_IPV6_MLD
* netif mld_mac_filter filter function must be called to add or delete an ipv6 entry in the multicast filter
  table of the ethernet MAC.
* The macro is not thread safe , and the  macro should be called after netif_add.
*/
#define netif_mld_mac_filter(netif, addr, action) do { if((netif) && (netif)->mld_mac_filter) { (netif)->mld_mac_filter((netif), (addr), (action)); }}while(0)
#endif /* LWIP_IPV6 && LWIP_IPV6_MLD */

#if ENABLE_LOOPBACK
err_t netif_loop_output(struct netif *netif, struct pbuf *p);
void netif_poll(struct netif *netif);
#if !LWIP_NETIF_LOOPBACK_MULTITHREADING
void netif_poll_all(void);
#endif /* !LWIP_NETIF_LOOPBACK_MULTITHREADING */
#endif /* ENABLE_LOOPBACK */

err_t netif_input(struct pbuf *p, struct netif *inp);

#if LWIP_IPV6
/** @ingroup netif_ip6 */
#define netif_ip_addr6(netif, i)  ((const ip_addr_t*)(&((netif)->ip6_addr[i])))
/** @ingroup netif_ip6 @endcond*/
#define netif_ip6_addr(netif, i)  ((const ip6_addr_t*)ip_2_ip6(&((netif)->ip6_addr[i])))
void netif_ip6_addr_set(struct netif *netif, s8_t addr_idx, const ip6_addr_t *addr6);
err_t netif_do_add_ipv6_addr(struct netif *netif, void *arguments);
err_t netif_do_rmv_ipv6_addr(struct netif *netif, void *arguments);

void netif_ip6_addr_set_parts(struct netif *netif, s8_t addr_idx, u32_t i0, u32_t i1, u32_t i2, u32_t i3);
#define netif_ip6_addr_state(netif, i)  ((netif)->ip6_addr_state[i])
void netif_ip6_addr_set_state(struct netif* netif, s8_t addr_idx, u8_t state);
s8_t netif_get_ip6_addr_match(struct netif *netif, const ip6_addr_t *ip6addr);
err_t netif_create_ip6_linklocal_address(struct netif *netif, u8_t from_mac_48bit);

err_t netif_get_ip6_linklocal_address(struct netif *netif, ip6_addr_t *addr);
err_t netif_add_ip6_address(struct netif *netif, const ip6_addr_t *ip6addr, s8_t *chosen_idx);

void netif_ip6_addr_setinvalid(struct netif *netif, const ip6_addr_t *addr6);

s8_t netif_get_ip6_preferred_addr_match(struct netif *netif, const ip6_addr_t *ip6addr);
struct netif *netif_find_by_ip6addr(const ip6_addr_t *ip6addr);

#if LWIP_IPV6_AUTOCONFIG
void netif_set_ip6_autoconfig_enabled(struct netif *netif);
void netif_set_ip6_autoconfig_disabled(struct netif *netif);
#endif /* LWIP_IPV6_AUTOCONFIG */

#if LWIP_IPV6_ADDRESS_LIFETIMES
#define netif_ip6_addr_valid_life(netif, i)  \
    (((netif) != NULL) ? ((netif)->ip6_addr_valid_life[i]) : IP6_ADDR_LIFE_STATIC)
#define netif_ip6_addr_set_valid_life(netif, i, secs) \
    do { if (netif != NULL) { (netif)->ip6_addr_valid_life[i] = (secs); }} while (0)
#define netif_ip6_addr_pref_life(netif, i)  \
    (((netif) != NULL) ? ((netif)->ip6_addr_pref_life[i]) : IP6_ADDR_LIFE_STATIC)
#define netif_ip6_addr_set_pref_life(netif, i, secs) \
    do { if (netif != NULL) { (netif)->ip6_addr_pref_life[i] = (secs); }} while (0)
#define netif_ip6_addr_isstatic(netif, i)  \
    (netif_ip6_addr_valid_life((netif), (i)) == IP6_ADDR_LIFE_STATIC)
#else /* !LWIP_IPV6_ADDRESS_LIFETIMES */
#define netif_ip6_addr_isstatic(netif, i)  (1) /* all addresses are static */
#endif /* !LWIP_IPV6_ADDRESS_LIFETIMES */

#if LWIP_IPV6_DHCP6
bool netif_ip6_addr_isdhcp6(struct netif *netif, s8_t i);
#else
#define netif_ip6_addr_isdhcp6(netif, i)  (0)
#endif

#if LWIP_ND6_ALLOW_RA_UPDATES
#define netif_mtu6(netif) ((netif)->mtu6)
#else /* LWIP_ND6_ALLOW_RA_UPDATES */
#define netif_mtu6(netif) ((netif)->mtu)
#endif /* LWIP_ND6_ALLOW_RA_UPDATES */
#endif /* LWIP_IPV6 */

#if LWIP_NETIF_HWADDRHINT
#define NETIF_SET_HWADDRHINT(netif, hint) ((netif)->addr_hint = (hint))
#else /* LWIP_NETIF_HWADDRHINT */
#define NETIF_SET_HWADDRHINT(netif, hint)
#endif /* LWIP_NETIF_HWADDRHINT */

struct netif *netif_find_by_ifindex(u8_t ifindex);
/*To identify as invalid index*/
#define LWIP_INVALID_IPV6_IDX 255

/* @ingroup netif */
u8_t netif_name_to_index(const char *name);
char *netif_index_to_name(u8_t uIndex, char *name);
err_t netif_get_nameindex_all(struct if_nameindex** pIfLst);


/* Interface indexes always start at 1 per RFC 3493, section 4, num starts at 0 .. 8 for padding */
#define IF_NAMEINDEX_ELE_SIZE    (sizeof(struct if_nameindex) + IFNAMSIZ + 4)

/* The interface index 0 is an invalid index */
struct netif* netif_get_by_index(u8_t idx);
#if defined (__cplusplus) && __cplusplus
}
#endif

#define NETIF_MTU_MIN 1280
#endif /* LWIP_HDR_NETIF_H */
