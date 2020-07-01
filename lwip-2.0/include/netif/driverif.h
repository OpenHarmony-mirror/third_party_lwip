/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved.
 * Copyright (c) <2013-2016>, <Huawei Technologies Co., Ltd>
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

 /*
 *********************************************************************************
 * Notice of Export Control Law
 * ===============================================
 * Huawei LiteOS may be subject to applicable export control laws and regulations, which
 * might include those applicable to Huawei LiteOS of U.S. and the country in which you
 * are located.
 * Import, export and usage of Huawei LiteOS in any manner by you shall be in compliance
 * with such applicable export control laws and regulations.
 *********************************************************************************
 */

#ifndef __DRIVERIF_H__
#define __DRIVERIF_H__
/**
 * @file driverif.h
 * @defgroup System_interfaces System Interfaces
 *  This contains all the system interfaces.
 */
#include "lwip/opt.h"
#include "netif/etharp.h"

#if defined (__cplusplus) && __cplusplus
extern "C" {
#endif

/** Type of link layer, these macros should be used for link_layer_type of struct netif */
#define LOOPBACK_IF         772
/** Type of link layer, these macros should be used for link_layer_type of struct netif */
#define ETHERNET_DRIVER_IF  1
/** Type of link layer, these macros should be used for link_layer_type of struct netif */
#define WIFI_DRIVER_IF      801

/** Short names of link layer */
#define LOOPBACK_IFNAME "lo"
/** Short names of link layer */
#define ETHERNET_IFNAME "eth"
/** Short names of link layer */
#define WIFI_IFNAME "wlan"

/**
* @defgroup Driver_Interfaces Driver Interfaces
* This section provides information about the Network driver related interfaces.
*/


/** Function pointer of driver send function */
typedef void (*drv_send_fn)(struct netif *netif, struct pbuf *p);

/** Function pointer of driver set hw address function */
/* This callback function should return 0 in case of success */
typedef u8_t (*drv_set_hwaddr_fn)(struct netif *netif, u8_t *addr, u8_t len);

err_t driverif_init(struct netif *netif);

#if LWIP_NETIF_PROMISC
/** Function pointer of driver set/unset promiscuous mode on interface */
typedef void (*drv_config_fn)(struct netif *netif, u32_t config_flags, u8_t setBit);
#endif  /* LWIP_NETIF_PROMISC */

/*
Func Name:  driverif_input
*/
/**
* @ingroup   Driver_Interfaces
* @brief     This API must be called by the network driver to pass the input packet to lwIP.
* Before calling this API, the driver has to keep the packet in the pbuf structure. The driver must
* call pbuf_alloc() with the type as PBUF_RAM to create the pbuf structure. The driver
* has to pass the pbuf structure to this API to add the pbuf into the TCPIP thread.
* After this packet is processed by TCPIP thread, pbuf will be freed. The driver is not required to
* free the pbuf.
* @param[in]    netif                 Indicates the lwIP network interface.
* @param[in]    p                     Indicates the packet in the pbuf structure.
* @return None
* @note
* None
*/
void  driverif_input(struct netif *netif, struct pbuf *p);

#if defined (__cplusplus) && __cplusplus
}
#endif

#endif

