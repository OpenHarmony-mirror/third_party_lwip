/**
 * @file
 * This is the IPv4 & IPv6 address tools implementation.
 *
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

#include "lwip/opt.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#if LWIP_IPV4 || LWIP_IPV6

#include "lwip/ip_addr.h"
#include "lwip/ip4_addr.h"
#include "lwip/netif.h"


#if LWIP_SOCKET_SET_ERRNO
#ifndef set_errno
#define set_errno(err) do { errno = (err); } while(0)
#endif
#else /* LWIP_SOCKET_SET_ERRNO */
#define set_errno(err)
#endif /* LWIP_SOCKET_SET_ERRNO */


#if LWIP_INET_ADDR_FUNC
in_addr_t inet_addr(const char *cp)
{
  LWIP_ERROR("inet_aton:cp is NULL", (cp != NULL), return (INADDR_NONE));
  return ipaddr_addr(cp);
}
#endif

#if LWIP_INET_ATON_FUNC
int inet_aton(const char *cp, struct in_addr *inp)
{
  LWIP_ERROR("inet_aton:cp is NULL", (cp != NULL), return 0);
  return ip4addr_aton(cp, (ip4_addr_t *)inp);
}
#endif

#if LWIP_INET_NTOA_FUNC
char* inet_ntoa(struct in_addr in)
{
  return ip4addr_ntoa((const ip4_addr_t *)&in);
}
#endif


const char *lwip_inet_ntop(int af, const void *src, char *dst, socklen_t size)
{
  const char *ret = NULL;

  switch (af) {
#if LWIP_IPV4
    case AF_INET:
      ret = lwip_inet_ntop4(src, dst, size);
      if (ret == NULL) {
        set_errno(ENOSPC);
      }
      break;
#endif /* LWIP_IPV4 */

#if LWIP_IPV6
    case AF_INET6:
      ret = ip6addr_ntoa_r((const ip6_addr_t*)(src), (dst), INET6_ADDRSTRLEN);
      if (ret == NULL) {
        set_errno(ENOSPC);
      }
      break;
#endif /* LWIP_IPV6 */
    default:
      set_errno(EAFNOSUPPORT);
      break;
  }

  return ret;
}

int lwip_inet_pton(int af, const char *src, void *dst)
{
  int err;

  switch (af) {
#if LWIP_IPV4
    case AF_INET:
      return inet_pton4(src, dst);
#endif /* LWIP_IPV4 */

#if LWIP_IPV6
    case AF_INET6:
    {
      /* convert into temporary variable since ip6_addr_t might be larger
         than in6_addr when scopes are enabled */
      ip6_addr_t addr;
      err = ip6addr_aton((src), &addr);
      if (err) {
        (void)memcpy(dst, addr.addr, sizeof(addr.addr));
      }

      return err;
#endif /* LWIP_IPV6 */
    }
    default:
      set_errno(EAFNOSUPPORT);
      break;
  }

  return -1;
}
#endif /* LWIP_IPV4 || LWIP_IPV6 */

