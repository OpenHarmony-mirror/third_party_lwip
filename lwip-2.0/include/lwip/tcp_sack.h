/**********************************************************************************
 * Copyright (c) <2013-2016>, <Huawei Technologies Co., Ltd>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation and/or
 * other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors
 * may be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 **********************************************************************************/

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

#ifndef __LWIP_TCP_SACK_CA__
#define __LWIP_TCP_SACK_CA__

#include "lwip/tcp.h"
#include "lwip/priv/tcp_priv.h"

#if defined (__cplusplus) && __cplusplus
extern "C" {
#endif


#define UNSACKED_AND_LOST_SEG       0x0001U
#define UNSENT_SEG                  0x0002U
#define UNSACKED_SEG                0x0004U
#define RESCUE_RX_SEG               0x0008U
#define SACK_SYNC_PERMITTED_OPTION  0x04020101U
#define SACK_OPTIONS                0x01010500UL
#define MAX_ORDER                   0xFFFFFFFF
#if DRIVER_STATUS_CHECK
#define FAST_RETX_SEG               0x0010U /* First Segment retransmitted as part of Fast retransmit algorithm */
#define SEG_TYPE_NONE               0x0000U
#endif

extern u32_t
tcp_parseopt_sack(u8_t *opts, u16_t c);

extern u32_t
tcp_sack_update(struct tcp_pcb *pcb, u32_t ackno);

extern void
tcp_sack_based_fast_rexmit_alg(struct tcp_pcb *pcb);

extern void
tcp_sack_based_loss_recovery_alg(struct tcp_pcb *pcb);

#if LWIP_SACK_PERF_OPT
extern void 
tcp_sack_rexmit_lost_rexmitted(struct tcp_pcb *pcb);
#endif

extern void
tcp_sack_set_pipe(struct tcp_pcb *pcb);

extern int
tcp_sack_is_lost(struct tcp_pcb *pcb, struct tcp_seg *seg);

void tcp_pcb_reset_sack_seq(struct tcp_pcb *pcb);
void tcp_update_sack_for_received_ooseq_segs(struct tcp_pcb *pcb);
void tcp_update_sack_fields_for_new_seg(struct tcp_seg *seg);
void tcp_enqueue_flags_sack(struct tcp_pcb *pcb, u8_t *optflags);
void tcp_build_sack_permitted_option(u32_t *opts);
u8_t tcp_get_sack_block_count_for_send(struct tcp_pcb *pcb, u8_t optlen);
void tcp_build_sack_option(struct tcp_pcb *pcb, u8_t cnt, u32_t *options);
void tcp_parseopt_sack_permitted(struct tcp_pcb *pcb);
void tcp_connect_update_sack(struct tcp_pcb *pcb, u32_t iss);
struct tcp_seg *tcp_sack_get_next_seg(struct tcp_pcb *pcb, u32_t next_seg_type);

#if LWIP_SACK_DATA_SEG_PIGGYBACK
#if LWIP_SACK
u8_t tcp_check_and_alloc_sack_options(struct tcp_seg *seg, struct tcp_pcb *pcb);
#endif
#endif
#if DRIVER_STATUS_CHECK
#if LWIP_SACK
void tcp_search_and_flush_sack_on_wake_queue(struct tcp_pcb *pcb, u32_t sack_type);
#endif
#endif
#if defined (__cplusplus) && __cplusplus
}
#endif

#endif
