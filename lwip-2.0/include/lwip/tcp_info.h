/*----------------------------------------------------------------------------
 * Copyright (c) <2013-2015>, <Huawei Technologies Co., Ltd>
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 * conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list
 * of conditions and the following disclaimer in the documentation and/or other materials
 * provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used
 * to endorse or promote products derived from this software without specific prior written
 * permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *---------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------
 * Notice of Export Control Law
 * ===============================================
 * Huawei LiteOS may be subject to applicable export control laws and regulations, which might
 * include those applicable to Huawei LiteOS of U.S. and the country in which you are located.
 * Import, export and usage of Huawei LiteOS in any manner by you shall be in compliance with such
 * applicable export control laws and regulations.
 *---------------------------------------------------------------------------*/

#ifndef __LWIP_TCP_INFO_H__
#define __LWIP_TCP_INFO_H__


#include "opt.h"
#include "arch/cc.h"
#include "lwip/priv/tcp_priv.h"

#ifdef LWIP_TCP
#if defined (__cplusplus) && __cplusplus
extern "C" {
#endif


/*
 * TCP FSM state definitions.
 * Per RFC793, September, 1981.
 */

#define TCP_NSTATES 11

/* for TCP_INFO socket option */
#define TCPI_OPT_TIMESTAMPS 1
#define TCPI_OPT_SACK       2
#define TCPI_OPT_WSCALE     4
#define TCPI_OPT_ECN        8 /* ECN was negociated at TCP session init */ /*Not supported in TCP_INFO*/
#define TCPI_OPT_ECN_SEEN   16 /* we received at least one packet with ECT */  /*Not supported in TCP_INFO*/
#define TCPI_OPT_SYN_DATA   32 /* SYN-ACK acked data in SYN sent or rcvd */ /*Not supported in TCP_INFO*/

#if !defined(LWIP_TCP_INFO) || (0 == LWIP_TCP_INFO)  || !LWIP_LITEOS_COMPAT
/**
* @cond liteos
* @defgroup Config_TCP  TCP Configuration Interfaces
* @ingroup  Configuration_Interfaces
*/

/**
* @defgroup Configuration_Interfaces Configuration Interfaces
* This contains all the configuration APIs
* @endcond
*/

/** This structure gives information about the TCP connection. */
struct tcp_info {
    u8_t    tcpi_state; /**<  Indicates state of a TCP connection. This is currently supported.*/
    u8_t  tcpi_ca_state; /**<  Indicates the CA state. This is currently set to 0.*/
    u8_t  tcpi_retransmits; /**<  Indicates retransmit. This is currently supported.*/
    u8_t  tcpi_probes; /**<  Indicates probes. This is currently supported.*/
    u8_t  tcpi_backoff; /**<  Indicates backoff. This is currently supported.*/
    u8_t  tcpi_options; /**<  Indicates options . This is currently supported.*/
    u8_t  tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4; /**<  Indicates send and receive of wscale.  This is currently set to 0.*/

    u32_t    tcpi_rto; /**<  Indicates rto. This is currently supported.*/
    u32_t    tcpi_ato; /**<  Indicates ato.  This is currently set to 0.*/
    u32_t    tcpi_snd_mss; /**<  Indicates the send message. This is currently supported.*/
    u32_t    tcpi_rcv_mss; /**<  Indicates the receive message state. This is currently supported.*/

    u32_t    tcpi_unacked; /**<  Indicates unacknowledge. This is currently supported.*/
    u32_t    tcpi_sacked; /**<  Indicates sack.  This is currently set to 0.*/
    u32_t    tcpi_lost;   /**<  Indicates lost packet.  This is currently set to 0.*/
    u32_t    tcpi_retrans;  /**<  Indicates retransmit.  This is currently set to 0.*/
    u32_t    tcpi_fackets;   /**<  Indicates fackets.  This is currently set to 0.*/

    /* Times. */
    u32_t    tcpi_last_data_sent;  /**<  Indicates the last data sent.  This is currently set to 0.*/
    u32_t    tcpi_last_ack_sent;   /**<  Indicates the last acknowledge sent. This is currently set to 0.*/
    u32_t    tcpi_last_data_recv;  /**<  Indicates last data receive.  This is currently set to 0.*/
    u32_t    tcpi_last_ack_recv;   /**<  Indicates the last acknowledge receive.  This is currently set to 0.*/

    /* Metrics. */
    u32_t    tcpi_pmtu;              /**<  Indicates mtu. This is currently set to 0.*/
    u32_t    tcpi_rcv_ssthresh;      /**<  Indicates slow start threshold receive. This is currently set to 0.*/
    u32_t    tcpi_rtt;               /**<  Indicates the rtt. This is currently supported.*/
    u32_t    tcpi_rttvar;            /**<  Indicates rttvar. This is currently supported.*/
    u32_t    tcpi_snd_ssthresh;     /**<  Indicates slow start threshold send. This is currently supported.*/
    u32_t    tcpi_snd_cwnd;        /**<  Indicates send cwnd. This is currently supported.*/
    u32_t    tcpi_advmss;          /**<  Indicates advmss. This is currently set to 0.*/
    u32_t    tcpi_reordering;     /**<  Indicates reordering. This is currently supported.*/

    u32_t    tcpi_rcv_rtt;     /**<  Indicates receive rtt.  This is currently set to 0.*/
    u32_t    tcpi_rcv_space;   /**<  Indicates TCPI receive space. This is currently set to 0.*/

    u32_t    tcpi_total_retrans;   /**<  Indicates total retransmit. This is currently set to 0.*/
};

#endif    /* !LWIP_TCP_INFO*/

void tcp_get_info(const struct tcp_pcb *pcb, struct tcp_info *tcpinfo);

#if defined (__cplusplus) && __cplusplus
}
#endif

#endif /* LWIP_TCP */
#endif /* __LWIP_TCP_CONFIG_H__ */
