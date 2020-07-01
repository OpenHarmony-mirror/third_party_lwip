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

#ifndef __ETHTOOL_H
#define __ETHTOOL_H


#include "lwip/opt.h"

/* don't build if not configured for use in lwipopts.h */
#if LWIP_NETIF_ETHTOOL
#include "lwip/netif.h"
#include "lwip/sockets.h"
#include "arch/cc.h"
#include "netif/ifaddrs.h"
#if LWIP_LITEOS_COMPAT && !LWIP_LINUX_COMPAT
#include <liteos/ethtool.h>
#endif

#if LWIP_LITEOS_COMPAT && LWIP_LINUX_COMPAT
#include <linux/ethtool.h>
#endif

#if defined (__cplusplus) && __cplusplus
extern "C" {
#endif

 /**
 *  @file ethtool.h
 *  This file provides information for ethtool.
 */
/* CMDs currently supported */
#if !LWIP_LITEOS_COMPAT
#define ETHTOOL_GSET    0x00000001 /* Get settings. */
#define ETHTOOL_SSET    0x00000002 /* Set settings. */
#define ETHTOOL_GDRVINFO  0x00000003 /* Get driver info. */
#define ETHTOOL_GREGS   0x00000004 /* Get NIC registers. */
#define ETHTOOL_GWOL    0x00000005 /* Get wake-on-lan options. */
#define ETHTOOL_SWOL    0x00000006 /* Set wake-on-lan options. */
#define ETHTOOL_GMSGLVL   0x00000007 /* Get driver message level */
#define ETHTOOL_SMSGLVL   0x00000008 /* Set driver msg level. */
#define ETHTOOL_NWAY_RST  0x00000009 /* Restart autonegotiation. */
/* Get link status for host, i.e. whether the interface *and* the
 * physical port (if there is one) are up (ethtool_value). */
#define ETHTOOL_GLINK   0x0000000a
#define ETHTOOL_GEEPROM   0x0000000b /* Get EEPROM data */
#define ETHTOOL_SEEPROM   0x0000000c /* Set EEPROM data. */
#define ETHTOOL_GCOALESCE 0x0000000e /* Get coalesce config */
#define ETHTOOL_SCOALESCE 0x0000000f /* Set coalesce config. */
#define ETHTOOL_GRINGPARAM  0x00000010 /* Get ring parameters */
#define ETHTOOL_SRINGPARAM  0x00000011 /* Set ring parameters. */
#define ETHTOOL_GPAUSEPARAM 0x00000012 /* Get pause parameters */
#define ETHTOOL_SPAUSEPARAM 0x00000013 /* Set pause parameters. */
#define ETHTOOL_GRXCSUM   0x00000014 /* Get RX hw csum enable (ethtool_value) */
#define ETHTOOL_SRXCSUM   0x00000015 /* Set RX hw csum enable (ethtool_value) */
#define ETHTOOL_GTXCSUM   0x00000016 /* Get TX hw csum enable (ethtool_value) */
#define ETHTOOL_STXCSUM   0x00000017 /* Set TX hw csum enable (ethtool_value) */
#define ETHTOOL_GSG   0x00000018 /* Get scatter-gather enable
              * (ethtool_value) */
#define ETHTOOL_SSG   0x00000019 /* Set scatter-gather enable
              * (ethtool_value). */
#define ETHTOOL_TEST    0x0000001a /* execute NIC self-test. */
#define ETHTOOL_GSTRINGS  0x0000001b /* get specified string set */
#define ETHTOOL_PHYS_ID   0x0000001c /* identify the NIC */
#define ETHTOOL_GSTATS    0x0000001d /* get NIC-specific statistics */
#define ETHTOOL_GTSO    0x0000001e /* Get TSO enable (ethtool_value) */
#define ETHTOOL_STSO    0x0000001f /* Set TSO enable (ethtool_value) */
#define ETHTOOL_GPERMADDR 0x00000020 /* Get permanent hardware address */
#define ETHTOOL_GUFO    0x00000021 /* Get UFO enable (ethtool_value) */
#define ETHTOOL_SUFO    0x00000022 /* Set UFO enable (ethtool_value) */
#define ETHTOOL_GGSO    0x00000023 /* Get GSO enable (ethtool_value) */
#define ETHTOOL_SGSO    0x00000024 /* Set GSO enable (ethtool_value) */
#define ETHTOOL_GFLAGS    0x00000025 /* Get flags bitmap(ethtool_value) */
#define ETHTOOL_SFLAGS    0x00000026 /* Set flags bitmap(ethtool_value) */
#define ETHTOOL_GPFLAGS   0x00000027 /* Get driver-private flags bitmap */
#define ETHTOOL_SPFLAGS   0x00000028 /* Set driver-private flags bitmap */

#define ETHTOOL_GRXFH   0x00000029 /* Get RX flow hash configuration */
#define ETHTOOL_SRXFH   0x0000002a /* Set RX flow hash configuration */
#define ETHTOOL_GGRO    0x0000002b /* Get GRO enable (ethtool_value) */
#define ETHTOOL_SGRO    0x0000002c /* Set GRO enable (ethtool_value) */
#define ETHTOOL_GRXRINGS  0x0000002d /* Get RX rings available for LB */
#define ETHTOOL_GRXCLSRLCNT 0x0000002e /* Get RX class rule count */
#define ETHTOOL_GRXCLSRULE  0x0000002f /* Get RX classification rule */
#define ETHTOOL_GRXCLSRLALL 0x00000030 /* Get all RX classification rule */
#define ETHTOOL_SRXCLSRLDEL 0x00000031 /* Delete RX classification rule */
#define ETHTOOL_SRXCLSRLINS 0x00000032 /* Insert RX classification rule */
#define ETHTOOL_FLASHDEV  0x00000033 /* Flash firmware to device */
#define ETHTOOL_RESET   0x00000034 /* Reset hardware */
#define ETHTOOL_SRXNTUPLE 0x00000035 /* Add an n-tuple filter to device */
#define ETHTOOL_GRXNTUPLE 0x00000036 /* deprecated */
#define ETHTOOL_GSSET_INFO  0x00000037 /* Get string set info */
#define ETHTOOL_GRXFHINDIR  0x00000038 /* Get RX flow hash indir'n table */
#define ETHTOOL_SRXFHINDIR  0x00000039 /* Set RX flow hash indir'n table */

#define ETHTOOL_GFEATURES 0x0000003a /* Get device offload settings */
#define ETHTOOL_SFEATURES 0x0000003b /* Change device offload settings */
#define ETHTOOL_GCHANNELS 0x0000003c /* Get no of channels */
#define ETHTOOL_SCHANNELS 0x0000003d /* Set no of channels */
#define ETHTOOL_SET_DUMP  0x0000003e /* Set dump settings */
#define ETHTOOL_GET_DUMP_FLAG 0x0000003f /* Get dump settings */
#define ETHTOOL_GET_DUMP_DATA 0x00000040 /* Get dump data */

/* Supported flag list */
#define SUPPORTED_10baseT_Half (1 << 0)
#define SUPPORTED_10baseT_Full (1 << 1)
#define SUPPORTED_100baseT_Half (1 << 2)
#define SUPPORTED_100baseT_Full (1 << 3)
#define SUPPORTED_1000baseT_Half (1 << 4)
#define SUPPORTED_1000baseT_Full (1 << 5)
#define SUPPORTED_Autoneg (1 << 6)
#define SUPPORTED_TP (1 << 7)
#define SUPPORTED_AUI (1 << 8)
#define SUPPORTED_MII (1 << 9)
#define SUPPORTED_FIBRE (1 << 10)
#define SUPPORTED_BNC (1 << 11)
#define SUPPORTED_10000baseT_Full (1 << 12)
#define SUPPORTED_Pause (1 << 13)
#define SUPPORTED_Asym_Pause (1 << 14)
#define SUPPORTED_2500baseX_Full (1 << 15)
#define SUPPORTED_Backplane (1 << 16)
#define SUPPORTED_1000baseKX_Full (1 << 17)
#define SUPPORTED_10000baseKX4_Full (1 << 18)
#define SUPPORTED_10000baseKR_Full (1 << 19)
#define SUPPORTED_10000baseR_FEC (1 << 20)
#define SUPPORTED_20000baseMLD2_Full (1 << 21)
#define SUPPORTED_20000baseKR2_Full (1 << 22)
#define SUPPORTED_40000baseKR4_Full (1 << 23)
#define SUPPORTED_40000baseCR4_Full (1 << 24)
#define SUPPORTED_40000baseSR4_Full (1 << 25)
#define SUPPORTED_40000baseLR4_Full (1 << 26)
#define SUPPORTED_56000baseKR4_Full (1 << 27)
#define SUPPORTED_56000baseCR4_Full (1 << 28)
#define SUPPORTED_56000baseSR4_Full (1 << 29)
#define SUPPORTED_56000baseLR4_Full (1 << 30)

/* Advertised flag list */
#define ADVERTISED_10baseT_Half (1 << 0)
#define ADVERTISED_10baseT_Full (1 << 1)
#define ADVERTISED_100baseT_Half (1 << 2)
#define ADVERTISED_100baseT_Full (1 << 3)
#define ADVERTISED_1000baseT_Half (1 << 4)
#define ADVERTISED_1000baseT_Full (1 << 5)
#define ADVERTISED_Autoneg (1 << 6)
#define ADVERTISED_TP (1 << 7)
#define ADVERTISED_AUI (1 << 8)
#define ADVERTISED_MII (1 << 9)
#define ADVERTISED_FIBRE (1 << 10)
#define ADVERTISED_BNC (1 << 11)
#define ADVERTISED_10000baseT_Full (1 << 12)
#define ADVERTISED_Pause (1 << 13)
#define ADVERTISED_Asym_Pause (1 << 14)
#define ADVERTISED_2500baseX_Full (1 << 15)
#define ADVERTISED_Backplane (1 << 16)
#define ADVERTISED_1000baseKX_Full (1 << 17)
#define ADVERTISED_10000baseKX4_Full (1 << 18)
#define ADVERTISED_10000baseKR_Full (1 << 19)
#define ADVERTISED_10000baseR_FEC (1 << 20)
#define ADVERTISED_20000baseMLD2_Full (1 << 21)
#define ADVERTISED_20000baseKR2_Full (1 << 22)
#define ADVERTISED_40000baseKR4_Full (1 << 23)
#define ADVERTISED_40000baseCR4_Full (1 << 24)
#define ADVERTISED_40000baseSR4_Full (1 << 25)
#define ADVERTISED_40000baseLR4_Full (1 << 26)
#define ADVERTISED_56000baseKR4_Full (1 << 27)
#define ADVERTISED_56000baseCR4_Full (1 << 28)
#define ADVERTISED_56000baseSR4_Full (1 << 29)
#define ADVERTISED_56000baseLR4_Full (1 << 30)

/* The forced speed, in units of 1Mb. */
#define SPEED_10 10
#define SPEED_100 100
#define SPEED_1000 1000
#define SPEED_2500 2500
#define SPEED_5000 5000
#define SPEED_10000 10000
#define SPEED_20000 20000
#define SPEED_25000 25000
#define SPEED_40000 40000
#define SPEED_50000 50000
#define SPEED_56000 56000
#define SPEED_100000 100000
#define SPEED_UNKNOWN -1

/* Duplex, half or full. */
#define DUPLEX_HALF 0x00
#define DUPLEX_FULL 0x01
#define DUPLEX_UNKNOWN 0xff

/* Which connector port. */
#define PORT_TP 0x00           /* An Ethernet interface using Twisted-Pair cable as the medium. */
#define PORT_AUI 0x01          /* Attachment Unit Interface (AUI). Normally used with hubs. */
#define PORT_MII 0x02          /* An Ethernet interface using a Media Independent Interface (MII). */
#define PORT_FIBRE 0x03        /* An Ethernet interface using Optical Fibre as the medium. */
#define PORT_BNC 0x04          /* An Ethernet interface using BNC connectors and co-axial cable. */
#define PORT_DA 0x05           /* Direct Attach Copper */
#define PORT_NONE 0xef
#define PORT_OTHER 0xff

/* Enable or disable autonegotiation. */
#define AUTONEG_DISABLE 0x00
#define AUTONEG_ENABLE 0x01

/* MDI or MDI-X status/control - if MDI/MDI_X/AUTO is set then
 * the driver is required to renegotiate link
 */
#define ETH_TP_MDI_INVALID 0x00  /* status: unknown; control: unsupported */
#define ETH_TP_MDI 0x01          /* status: MDI;     control: force MDI */
#define ETH_TP_MDI_X 0x02        /* status: MDI-X;   control: force MDI-X */
#define ETH_TP_MDI_AUTO 0x03     /*                  control: auto-select */

/* Device supports clause 22 register access to PHY or peripherals
 * using the interface. */
#define ETH_MDIO_SUPPORTS_C22 1
/* Device supports clause 45 register access to PHY or peripherals
 * using the interface. */
#define ETH_MDIO_SUPPORTS_C45 2

/** @brief This struct is to pass data for link control and status */
struct ethtool_cmd {
  /** < Command number = %ETHTOOL_GSET or %ETHTOOL_SSET */
  u32_t cmd;
  /** < Bitmask of %SUPPORTED_* flags for the link modes, physical connectors and other link features
   for which the interface supports autonegotiation or auto-detection. Read-only. */
  u32_t supported;
  /** < Bitmask of %ADVERTISED_* flags for the link modes, physical connectors and other link features
   that are advertised through autonegotiation or enabled for auto-detection. */
  u32_t advertising;
  /** < Low bits of the speed, 1Mb units, 0 to INT_MAX or SPEED_UNKNOWN */
  u16_t speed;
  /** < Duplex mode; one of %DUPLEX_* */
  u8_t duplex;
  /** < Physical connector type; one of %PORT_* */
  u8_t port;
  /** < MDIO address of PHY (transceiver); 0 or 255 if not applicable. */
  u8_t phy_address;
  /** < Historically used to distinguish different possible PHY types,
   but not in a consistent way.  Deprecated. */
  u8_t transceiver;
  /** < Enable/disable autonegotiation and auto-detection; either %AUTONEG_DISABLE or %AUTONEG_ENABLE */
  u8_t autoneg;
  /** < Bitmask of %ETH_MDIO_SUPPORTS_* flags for the MDIO protocols supported by the interface;
   0 if unknown. Read-only. */
  u8_t mdio_support;
  /** < Historically used to report TX IRQ coalescing; Read-only; deprecated. */
  u32_t maxtxpkt;
  /** < Historically used to report RX IRQ coalescing; Read-only; deprecated. */
  u32_t maxrxpkt;
  /** < High bits of the speed, 1Mb units, 0 to INT_MAX or SPEED_UNKNOWN */
  u16_t speed_hi;
  /** < Ethernet twisted-pair MDI(-X) status; one of %ETH_TP_MDI_*. If the status is unknown or not applicable,
   the value will be %ETH_TP_MDI_INVALID. Read-only. */
  u8_t eth_tp_mdix;
  /** < Ethernet twisted pair MDI(-X) control; one of %ETH_TP_MDI_*.
   If MDI(-X) control is not implemented, reads yield %ETH_TP_MDI_INVALID and writes may be ignored or rejected.
   When written successfully, the link should be renegotiated if necessary. */
  u8_t eth_tp_mdix_ctrl;
  /** < Bitmask of %ADVERTISED_* flags for the link modes and other link features
   that the link partner advertised through autonegotiation; 0 if unknown or not applicable. Read-only. */
  u32_t lp_advertising;
  /* reserved 8(sizoef(u32_t) * 2) bytes */
  u32_t reserved[2];
};

/** @brief This structure is for passing single values. */
struct ethtool_value {
  u32_t cmd; /** < Indicates command. */
  u32_t data; /** < Indicates data. */
};
#endif

/**
 * @brief  Provides optional netdev operations.
 *
 * All operations are optional (that is, the function pointer may be set
 * to %NULL) and callers must take this into account.  Callers must
 * hold the RTNL lock.
 *
 * See the structures used by these operations for further documentation.
 *
 * See &struct net_device and &struct net_device_ops for documentation
 * of the generic netdev features interface.
 */
struct ethtool_ops {
  /** < Reports whether physical link is up.
    Will only be called if the netdev is up.
    Should usually be set to ethtool_op_get_link(), which uses netif_carrier_ok(). */
  s32_t (*get_link)(struct netif *netif);
  s32_t (*get_settings)(struct netif *netif, struct ethtool_cmd *cmd); /** < Gets the current settings */
  s32_t (*set_settings)(struct netif *netif, struct ethtool_cmd *cmd); /** < Configures settings */
  /** < Function to be called before any other operation.  Returns a  negative error code or zero. */
  int (*begin)(struct netif *netif);
  /** < Function to be called after any other operation except @begin.
     Will be called even if the other operation failed. */
  void (*complete)(struct netif *netif);
};

s32_t dev_ethtool(struct netif *netif, struct ifreq *ifr);
#if defined (__cplusplus) && __cplusplus
}
#endif

#endif /* LWIP_NETIF_ETHTOOL */

#endif /* __ETHTOOL_H */

