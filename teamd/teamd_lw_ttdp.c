/*
 *   teamd_lw_ttdp.c teamd TTDP link watcher
 *   Copyright (C) 2017-2018 Westermo
 *   Author: Andrzej Koszela <andy@ehostunrea.ch>
 *
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 *   Description:
 *   This file contains the TTDP linkwatcher.
 *
 *   The ttdp linkwatcher implements parts of the TTDP protocol, specifically relating to neighbor
 *   discovery via TTDP HELLO packets. The linkwatcher maintains two link states for its link;
 *   a "logical" state, determined by whether the port is receiving valid TTDP HELLO frames, and a
 *   "physical" state, which is determined by the physical link status received from the NIC driver
 *   (aka the ethtool link status). If both these states are true, the link is considered up. The
 *   linkwatcher also includes some configurable state transition logic which attempts to reduce the
 *   number of spurious link state transitions.
 *
 *   See the WeOS IEC61375 README for more information.
 */

#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/if_ether.h>
#include <netdb.h>
#include <inttypes.h>
#include <private/misc.h>
#include <linux/netdevice.h>
#include <ctype.h>
#include "teamd.h"
#include "teamd_link_watch.h"
#include "teamd_config.h"
#include "teamd_workq.h"
#include "teamd_lw_ttdp.h"

uint16_t frame_checksum(const uint8_t *cp, int len, int cisco, int out);

#define IFNAME_OR_EMPTY(P) ((P && P->start.common.tdport && P->start.common.tdport->ifname)\
	? P->start.common.tdport->ifname : "ttdp-lw")
#ifdef DEBUG
#define teamd_ttdp_log_infox(P, format, args...) daemon_log(LOG_DEBUG, "%s: " format, IFNAME_OR_EMPTY(P), ## args)
#define teamd_ttdp_log_dbgx(P, format, args...) daemon_log(LOG_DEBUG, "%s: " format, IFNAME_OR_EMPTY(P), ## args)
#else
#define teamd_ttdp_log_infox(P, format, args...) do {} while (0)
#define teamd_ttdp_log_dbgx(P, format, args...) do {} while (0)
#endif
#define teamd_ttdp_log_info(format, args...) daemon_log(LOG_INFO, format, ## args)
#define teamd_ttdp_log_dbg(format, args...) daemon_log(LOG_DEBUG, format, ## args)


/* BPF types */

/* Filters out only TTDP HELLO packets, based on the following:
 * (see ttdp_hello.bpf for the raw source code, also copied below)
 *    destination MAC 0x0180C200000E
 *    EtherType 0x8100
 *    VLAN ID 0x01EC
 *    Encapsulated proto 0x88CC
 *  If these match, then check the first 10 LLDP TLVs
 *  (code duplicated since BPF disallows loops):
 *    If TLV type is 0xFE00 and TLV length is 0x56, accept
 *	  If TLV type is 0xFE00 but length differs, skip that TLV
 *    If TLV claims to exceed packet boundary, drop entire packet
 *    If TLV has type 0, drop the entire packet (EOL TLV)
 *
 *
 *    Drop packet if no TLV matches (to ignore regular LLDP)
 */

static struct sock_filter ttdp_hello_filter[] = {
	{ 0x20,  0,  0, 0x00000002 },	/*   ld [2]                    ; check dest. MAC and other Ethernet stuff */
	{ 0x15,  0, 215, 0xc200000e },	/*   jneq #0xc200000e, drop */
	{ 0x28,  0,  0, 0000000000 },	/*   ldh [0] */
	{ 0x15,  0, 213, 0x00000180 },	/*   jneq #0x0180, drop */
	{ 0x20,  0,  0, 0xfffff030 },	/*   ld vlan_avail */
	{ 0x15,  0, 211, 0x00000001 },	/*   jneq #1, drop */
	{ 0x20,  0,  0, 0xfffff02c },	/*   ld vlan_tci */
	{ 0x54,  0,  0, 0x00000fff },	/*   and #0x0FFF */
	{ 0x15,  0, 208, 0x000001ec },	/*   jneq #0x01EC, drop */
	{ 0x28,  0,  0, 0x0000000c },	/*   ldh [12] */
	{ 0x15,  0, 206, 0x000088cc },	/*   jneq #0x88CC, drop */
	{ 0x20,  0,  0, 0xfffff034 },	/*   ld poff                   ; have M[0] hold the last ok header start position */
	{ 0x07,  0,  0, 0000000000 },	/*   tax */
	{ 0x80,  0,  0, 0000000000 },	/*   ld len */
	{ 0x1c,  0,  0, 0000000000 },	/*   sub x */
	{ 0x14,  0,  0, 0x00000002 },	/*   sub #2                    ; size of the first TLV header */
	{ 0x02,  0,  0, 0000000000 },	/*   st M[0] */
	{ 0000,  0,  0, 0x0000000e },	/*   ld #0x0e                  ; the first TLV header starts here */
	{ 0x01,  0,  0, 0000000000 },	/*   ldx #0x0 */
	{ 0x02,  0,  0, 0x00000001 },	/*   st M[1]                   ; this snippet tests whether we'd */
	{ 0x03,  0,  0, 0x00000002 },	/*   stx M[2]                  ; jump out of bounds, i.e. if  */
	{ 0x60,  0,  0, 0000000000 },	/*   ld M[0]                   ; ((accumulated TLV sizes in x) -  */
	{ 0x61,  0,  0, 0x00000001 },	/*   ldx M[1]                  ; (packet payload size)) < 0 */
	{ 0x1c,  0,  0, 0000000000 },	/*   sub x */
	{ 0x45, 192,  0, 0x80000000 },	/*   jset #0x80000000, drop */
	{ 0x60,  0,  0, 0x00000001 },	/*   ld M[1] */
	{ 0x61,  0,  0, 0x00000002 },	/*   ldx M[2] */
	{ 0x07,  0,  0, 0000000000 },	/*   tax */
	{ 0x48,  0,  0, 0000000000 },	/*   ldh [x + 0]               ; test one TLV - load TLV header */
	{ 0x54,  0,  0, 0x0000fe00 },	/*   and #0xFE00               ; extract type */
	{ 0x15, 186,  0, 0000000000 },	/*   jeq #0x0000, drop         ; type 0 is EOF TLV */
	{ 0x15,  0,  3, 0x0000fe00 },	/*   jneq #0xFE00, skip_tlv_1  ; skip if not HELLO */
	{ 0x48,  0,  0, 0000000000 },	/*   ldh [x + 0]               ; reload TLV header */
	{ 0x54,  0,  0, 0x000001ff },	/*   and #0x01FF               ; extract length */
	{ 0x15, 181,  0, 0x00000056 },	/*   jeq #0x56, okay           ; must be 86 */
	{ 0x48,  0,  0, 0000000000 },	/* skip_tlv_1: ldh [x + 0]     ; reload TLV header */
	{ 0x54,  0,  0, 0x000001ff },	/*   and #0x01FF               ; extract length */
	{ 0x04,  0,  0, 0x00000002 },	/*   add #2                    ; header length not included */
	{ 0x0c,  0,  0, 0000000000 },	/*   add x                     ; previous header offset */
	{ 0x02,  0,  0, 0x00000001 },	/*   st M[1] */
	{ 0x03,  0,  0, 0x00000002 },	/*   stx M[2] */
	{ 0x60,  0,  0, 0000000000 },	/*   ld M[0] */
	{ 0x61,  0,  0, 0x00000001 },	/*   ldx M[1] */
	{ 0x1c,  0,  0, 0000000000 },	/*   sub x */
	{ 0x45, 172,  0, 0x80000000 },	/*   jset #0x80000000, drop */
	{ 0x60,  0,  0, 0x00000001 },	/*   ld M[1] */
	{ 0x61,  0,  0, 0x00000002 },	/*   ldx M[2] */
	{ 0x07,  0,  0, 0000000000 },	/*   tax */
	{ 0x48,  0,  0, 0000000000 },	/*   ldh [x + 0]               ; test next TLV... etc */
	{ 0x54,  0,  0, 0x0000fe00 },	/*   and #0xFE00 */
	{ 0x15, 166,  0, 0000000000 },	/*   jeq #0x0000, drop */
	{ 0x15,  0,  3, 0x0000fe00 },	/*   jneq #0xFE00, skip_tlv_2 */
	{ 0x48,  0,  0, 0000000000 },	/*   ldh [x + 0] */
	{ 0x54,  0,  0, 0x000001ff },	/*   and #0x01FF */
	{ 0x15, 161,  0, 0x00000056 },	/*   jeq #0x56, okay */
	{ 0x48,  0,  0, 0000000000 },	/* skip_tlv_2: ldh [x + 0] */
	{ 0x54,  0,  0, 0x000001ff },	/*   and #0x01FF */
	{ 0x04,  0,  0, 0x00000002 },	/*   add #2 */
	{ 0x0c,  0,  0, 0000000000 },	/*   add x */
	{ 0x02,  0,  0, 0x00000001 },	/*   st M[1] */
	{ 0x03,  0,  0, 0x00000002 },	/*   stx M[2] */
	{ 0x60,  0,  0, 0000000000 },	/*   ld M[0] */
	{ 0x61,  0,  0, 0x00000001 },	/*   ldx M[1] */
	{ 0x1c,  0,  0, 0000000000 },	/*   sub x */
	{ 0x45, 152,  0, 0x80000000 },	/*   jset #0x80000000, drop */
	{ 0x60,  0,  0, 0x00000001 },	/*   ld M[1] */
	{ 0x61,  0,  0, 0x00000002 },	/*   ldx M[2] */
	{ 0x07,  0,  0, 0000000000 },	/*   tax */
	{ 0x48,  0,  0, 0000000000 },	/*   ldh [x + 0] */
	{ 0x54,  0,  0, 0x0000fe00 },	/*   and #0xFE00 */
	{ 0x15, 146,  0, 0000000000 },	/*   jeq #0x0000, drop */
	{ 0x15,  0,  3, 0x0000fe00 },	/*   jneq #0xFE00, skip_tlv_3 */
	{ 0x48,  0,  0, 0000000000 },	/*   ldh [x + 0] */
	{ 0x54,  0,  0, 0x000001ff },	/*   and #0x01FF */
	{ 0x15, 141,  0, 0x00000056 },	/*   jeq #0x56, okay */
	{ 0x48,  0,  0, 0000000000 },	/* skip_tlv_3: ldh [x + 0] */
	{ 0x54,  0,  0, 0x000001ff },	/*   and #0x01FF */
	{ 0x04,  0,  0, 0x00000002 },	/*   add #2 */
	{ 0x0c,  0,  0, 0000000000 },	/*   add x */
	{ 0x02,  0,  0, 0x00000001 },	/*   st M[1] */
	{ 0x03,  0,  0, 0x00000002 },	/*   stx M[2] */
	{ 0x60,  0,  0, 0000000000 },	/*   ld M[0] */
	{ 0x61,  0,  0, 0x00000001 },	/*   ldx M[1] */
	{ 0x1c,  0,  0, 0000000000 },	/*   sub x */
	{ 0x45, 132,  0, 0x80000000 },	/*   jset #0x80000000, drop */
	{ 0x60,  0,  0, 0x00000001 },	/*   ld M[1] */
	{ 0x61,  0,  0, 0x00000002 },	/*   ldx M[2] */
	{ 0x07,  0,  0, 0000000000 },	/*   tax */
	{ 0x48,  0,  0, 0000000000 },	/*   ldh [x + 0] */
	{ 0x54,  0,  0, 0x0000fe00 },	/*   and #0xFE00 */
	{ 0x15, 126,  0, 0000000000 },	/*   jeq #0x0000, drop */
	{ 0x15,  0,  3, 0x0000fe00 },	/*   jneq #0xFE00, skip_tlv_4 */
	{ 0x48,  0,  0, 0000000000 },	/*   ldh [x + 0] */
	{ 0x54,  0,  0, 0x000001ff },	/*   and #0x01FF */
	{ 0x15, 121,  0, 0x00000056 },	/*   jeq #0x56, okay */
	{ 0x48,  0,  0, 0000000000 },	/* skip_tlv_4: ldh [x + 0] */
	{ 0x54,  0,  0, 0x000001ff },	/*   and #0x01FF */
	{ 0x04,  0,  0, 0x00000002 },	/*   add #2 */
	{ 0x0c,  0,  0, 0000000000 },	/*   add x */
	{ 0x02,  0,  0, 0x00000001 },	/*   st M[1] */
	{ 0x03,  0,  0, 0x00000002 },	/*   stx M[2] */
	{ 0x60,  0,  0, 0000000000 },	/*   ld M[0] */
	{ 0x61,  0,  0, 0x00000001 },	/*   ldx M[1] */
	{ 0x1c,  0,  0, 0000000000 },	/*   sub x */
	{ 0x45, 112,  0, 0x80000000 },	/*   jset #0x80000000, drop */
	{ 0x60,  0,  0, 0x00000001 },	/*   ld M[1] */
	{ 0x61,  0,  0, 0x00000002 },	/*   ldx M[2] */
	{ 0x07,  0,  0, 0000000000 },	/*   tax */
	{ 0x48,  0,  0, 0000000000 },	/*   ldh [x + 0] */
	{ 0x54,  0,  0, 0x0000fe00 },	/*   and #0xFE00 */
	{ 0x15, 106,  0, 0000000000 },	/*   jeq #0x0000, drop */
	{ 0x15,  0,  3, 0x0000fe00 },	/*   jneq #0xFE00, skip_tlv_5 */
	{ 0x48,  0,  0, 0000000000 },	/*   ldh [x + 0] */
	{ 0x54,  0,  0, 0x000001ff },	/*   and #0x01FF */
	{ 0x15, 101,  0, 0x00000056 },	/*   jeq #0x56, okay */
	{ 0x48,  0,  0, 0000000000 },	/* skip_tlv_5: ldh [x + 0] */
	{ 0x54,  0,  0, 0x000001ff },	/*   and #0x01FF */
	{ 0x04,  0,  0, 0x00000002 },	/*   add #2 */
	{ 0x0c,  0,  0, 0000000000 },	/*   add x */
	{ 0x02,  0,  0, 0x00000001 },	/*   st M[1] */
	{ 0x03,  0,  0, 0x00000002 },	/*   stx M[2] */
	{ 0x60,  0,  0, 0000000000 },	/*   ld M[0] */
	{ 0x61,  0,  0, 0x00000001 },	/*   ldx M[1] */
	{ 0x1c,  0,  0, 0000000000 },	/*   sub x */
	{ 0x45, 92,  0, 0x80000000 },	/*   jset #0x80000000, drop */
	{ 0x60,  0,  0, 0x00000001 },	/*   ld M[1] */
	{ 0x61,  0,  0, 0x00000002 },	/*   ldx M[2] */
	{ 0x07,  0,  0, 0000000000 },	/*   tax */
	{ 0x48,  0,  0, 0000000000 },	/*   ldh [x + 0] */
	{ 0x54,  0,  0, 0x0000fe00 },	/*   and #0xFE00 */
	{ 0x15, 86,  0, 0000000000 },	/*   jeq #0x0000, drop */
	{ 0x15,  0,  3, 0x0000fe00 },	/*   jneq #0xFE00, skip_tlv_6 */
	{ 0x48,  0,  0, 0000000000 },	/*   ldh [x + 0] */
	{ 0x54,  0,  0, 0x000001ff },	/*   and #0x01FF */
	{ 0x15, 81,  0, 0x00000056 },	/*   jeq #0x56, okay */
	{ 0x48,  0,  0, 0000000000 },	/* skip_tlv_6: ldh [x + 0] */
	{ 0x54,  0,  0, 0x000001ff },	/*   and #0x01FF */
	{ 0x04,  0,  0, 0x00000002 },	/*   add #2 */
	{ 0x0c,  0,  0, 0000000000 },	/*   add x */
	{ 0x02,  0,  0, 0x00000001 },	/*   st M[1] */
	{ 0x03,  0,  0, 0x00000002 },	/*   stx M[2] */
	{ 0x60,  0,  0, 0000000000 },	/*   ld M[0] */
	{ 0x61,  0,  0, 0x00000001 },	/*   ldx M[1] */
	{ 0x1c,  0,  0, 0000000000 },	/*   sub x */
	{ 0x45, 72,  0, 0x80000000 },	/*   jset #0x80000000, drop */
	{ 0x60,  0,  0, 0x00000001 },	/*   ld M[1] */
	{ 0x61,  0,  0, 0x00000002 },	/*   ldx M[2] */
	{ 0x07,  0,  0, 0000000000 },	/*   tax */
	{ 0x48,  0,  0, 0000000000 },	/*   ldh [x + 0] */
	{ 0x54,  0,  0, 0x0000fe00 },	/*   and #0xFE00 */
	{ 0x15, 66,  0, 0000000000 },	/*   jeq #0x0000, drop */
	{ 0x15,  0,  3, 0x0000fe00 },	/*   jneq #0xFE00, skip_tlv_7 */
	{ 0x48,  0,  0, 0000000000 },	/*   ldh [x + 0] */
	{ 0x54,  0,  0, 0x000001ff },	/*   and #0x01FF */
	{ 0x15, 61,  0, 0x00000056 },	/*   jeq #0x56, okay */
	{ 0x48,  0,  0, 0000000000 },	/* skip_tlv_7: ldh [x + 0] */
	{ 0x54,  0,  0, 0x000001ff },	/*   and #0x01FF */
	{ 0x04,  0,  0, 0x00000002 },	/*   add #2 */
	{ 0x0c,  0,  0, 0000000000 },	/*   add x */
	{ 0x02,  0,  0, 0x00000001 },	/*   st M[1] */
	{ 0x03,  0,  0, 0x00000002 },	/*   stx M[2] */
	{ 0x60,  0,  0, 0000000000 },	/*   ld M[0] */
	{ 0x61,  0,  0, 0x00000001 },	/*   ldx M[1] */
	{ 0x1c,  0,  0, 0000000000 },	/*   sub x */
	{ 0x45, 52,  0, 0x80000000 },	/*   jset #0x80000000, drop */
	{ 0x60,  0,  0, 0x00000001 },	/*   ld M[1] */
	{ 0x61,  0,  0, 0x00000002 },	/*   ldx M[2] */
	{ 0x07,  0,  0, 0000000000 },	/*   tax */
	{ 0x48,  0,  0, 0000000000 },	/*   ldh [x + 0] */
	{ 0x54,  0,  0, 0x0000fe00 },	/*   and #0xFE00 */
	{ 0x15, 46,  0, 0000000000 },	/*   jeq #0x0000, drop */
	{ 0x15,  0,  3, 0x0000fe00 },	/*   jneq #0xFE00, skip_tlv_8 */
	{ 0x48,  0,  0, 0000000000 },	/*   ldh [x + 0] */
	{ 0x54,  0,  0, 0x000001ff },	/*   and #0x01FF */
	{ 0x15, 41,  0, 0x00000056 },	/*   jeq #0x56, okay */
	{ 0x48,  0,  0, 0000000000 },	/* skip_tlv_8: ldh [x + 0] */
	{ 0x54,  0,  0, 0x000001ff },	/*   and #0x01FF */
	{ 0x04,  0,  0, 0x00000002 },	/*   add #2 */
	{ 0x0c,  0,  0, 0000000000 },	/*   add x */
	{ 0x02,  0,  0, 0x00000001 },	/*   st M[1] */
	{ 0x03,  0,  0, 0x00000002 },	/*   stx M[2] */
	{ 0x60,  0,  0, 0000000000 },	/*   ld M[0] */
	{ 0x61,  0,  0, 0x00000001 },	/*   ldx M[1] */
	{ 0x1c,  0,  0, 0000000000 },	/*   sub x */
	{ 0x45, 32,  0, 0x80000000 },	/*   jset #0x80000000, drop */
	{ 0x60,  0,  0, 0x00000001 },	/*   ld M[1] */
	{ 0x61,  0,  0, 0x00000002 },	/*   ldx M[2] */
	{ 0x07,  0,  0, 0000000000 },	/*   tax */
	{ 0x48,  0,  0, 0000000000 },	/*   ldh [x + 0] */
	{ 0x54,  0,  0, 0x0000fe00 },	/*   and #0xFE00 */
	{ 0x15, 26,  0, 0000000000 },	/*   jeq #0x0000, drop */
	{ 0x15,  0,  3, 0x0000fe00 },	/*   jneq #0xFE00, skip_tlv_9 */
	{ 0x48,  0,  0, 0000000000 },	/*   ldh [x + 0] */
	{ 0x54,  0,  0, 0x000001ff },	/*   and #0x01FF */
	{ 0x15, 21,  0, 0x00000056 },	/*   jeq #0x56, okay */
	{ 0x48,  0,  0, 0000000000 },	/* skip_tlv_9: ldh [x + 0] */
	{ 0x54,  0,  0, 0x000001ff },	/*   and #0x01FF */
	{ 0x04,  0,  0, 0x00000002 },	/*   add #2 */
	{ 0x0c,  0,  0, 0000000000 },	/*   add x */
	{ 0x02,  0,  0, 0x00000001 },	/*   st M[1] */
	{ 0x03,  0,  0, 0x00000002 },	/*   stx M[2] */
	{ 0x60,  0,  0, 0000000000 },	/*   ld M[0] */
	{ 0x61,  0,  0, 0x00000001 },	/*   ldx M[1] */
	{ 0x1c,  0,  0, 0000000000 },	/*   sub x */
	{ 0x45, 12,  0, 0x80000000 },	/*   jset #0x80000000, drop */
	{ 0x60,  0,  0, 0x00000001 },	/*   ld M[1] */
	{ 0x61,  0,  0, 0x00000002 },	/*   ldx M[2] */
	{ 0x07,  0,  0, 0000000000 },	/*   tax */
	{ 0x48,  0,  0, 0000000000 },	/*   ldh [x + 0] */
	{ 0x54,  0,  0, 0x0000fe00 },	/*   and #0xFE00 */
	{ 0x15,  6,  0, 0000000000 },	/*   jeq #0x0000, drop */
	{ 0x15,  0,  5, 0x0000fe00 },	/*   jneq #0xFE00, drop */
	{ 0x48,  0,  0, 0000000000 },	/*   ldh [x + 0] */
	{ 0x54,  0,  0, 0x000001ff },	/*   and #0x01FF */
	{ 0x15,  1,  0, 0x00000056 },	/*   jeq #0x56, okay */
	{ 0x05,  0,  0, 0x00000001 },	/*   jmp drop */
	{ 0x06,  0,  0, 0xffffffff },	/*   okay: ret #-1             ; accept entire packet */
	{ 0x06,  0,  0, 0000000000 },	/*   drop: ret #0              ; accept nothing */
};

static struct sock_fprog ttdp_hello_fprog = {
	.len = (sizeof(ttdp_hello_filter)/sizeof(ttdp_hello_filter[0])),
	.filter = ttdp_hello_filter
};

/* Ethernet frame header including VLAN tag */
struct ttdp_frame_header {
	struct ether_header ether_header;
	u_int16_t vlan_tags;
	u_int16_t enc_ethertype;
} __attribute__((packed));

/* The following definitions of the TLVs (mandatory LLDP ones
 * and the TTDP-specific HELLO TLV) and default values for their
 * fields are taken from IEC 61375-2-5:2014 */
struct ttdp_lldp_tlv_header {
	u_int16_t header;
} __attribute__((packed));
#define TTDP_MAKE_TLV_TYPE_LEN(type, len) (ntohs(((type & 0x7F) << 9) | (len & 0x1FF)))

struct ttdp_default_lldp_chassis_tlv {
	struct ttdp_lldp_tlv_header header;	/* type 1, length 7 */
	u_int8_t chassisIdSubtype;			/* default: 4 */
	struct ether_addr chassisId;		/* default: MAC of sender */
} __attribute__((packed));

/* NOTE: This TLV follows the example in IEC 61375-2-5:2014 while the other
 * implementation instead uses subtype 6 with a sender MAC address payload
 * (just like the chassis TLV) - see below */
struct ttdp_default_lldp_port_tlv {
	struct ttdp_lldp_tlv_header header;	/* type 2, length 2 */
	u_int8_t portIdSubtype;				/* default: 6 */
	u_int8_t portId;					/* default: "ETB, ETBN egress physical port nb" */
} __attribute__((packed));

/* This is how the implementation in WeOS 4.x does it */
struct ttdp_legacy_lldp_port_tlv {
	struct ttdp_lldp_tlv_header header;	/* type 2, length 7 */
	u_int8_t portIdSubtype;				/* default: 3 */
	struct ether_addr mac;
} __attribute__((packed));

struct ttdp_default_lldp_ttl_tlv {
	struct ttdp_lldp_tlv_header header;	/* type 3, length 2 */
	u_int16_t ttl;						/* default: LLDP TTL (seconds) */
} __attribute__((packed));

struct ttdp_default_lldp_eol_tlv {
	struct ttdp_lldp_tlv_header header;	/* type 0, length 0 */
} __attribute__((packed));

struct ttdp_hello_tlv {
	struct ttdp_lldp_tlv_header header;	/* type 127, length 86 */
	u_int8_t oui[3];					/* IEC TC9 WG43 Organizationally Unique ID */
										/*  default: 0x200E95 */
	u_int8_t ttdpSubtype;				/* TTDP HELLO TLV subtype, default: 1 */
	u_int16_t tlvCS;					/* TLV checksum */
	u_int32_t version;					/* HELLO TLV version, default: 0x01000000 */
	u_int32_t lifeSign;					/* sequence number (increases) */
	u_int32_t etbTopoCnt;				/* topo counter; CRC32 of the TND */
	u_int8_t vendor[32];				/* Vendor specific info */
	u_int8_t recvStatuses;				/* receive line A-D statuses (bitfield, 2 bits
										 *  per line, A to the left, see IEC61375-2-5:2014
										 *  section 8.7.5) */
	u_int8_t timeoutSpeed;				/* timeout speed - slow mode (1) or fast mode (2) */
	struct ether_addr srcId;			/* sender MAC */
	u_int8_t srcPortId;					/* ETB, ETBN egress physical port number - the meaning
										 *  of this field is not clearly defined; used here as
										 *  which physical port this frame was sent from. Same
										 *  meaning as portId in the port TLV. */
	u_int8_t egressLine;				/* Which ETB line we sent this on */
	u_int8_t egressDir;					/* Which direction we sent this in */
	/* reserved1; */					/* Shared byte with the field below */
	u_int8_t inaugInhibition;			/* Inauguration inhibition status */
	struct ether_addr remoteId;			/* Last known MAC of the neighbor on this line
										 *  in this direction */
	u_int16_t reserved2;				/* padding */
	u_int8_t cstUUid[16];				/* UUID of the local consist */
} __attribute__((packed));

/* Change the definition below to to use either the "example" port TLV,
 * or the 4.x one */
struct ttdp_default_hello_frame {
	struct ttdp_frame_header frame_header; 				/* Ethernet & VLAN headers */
	struct ttdp_default_lldp_chassis_tlv chassis_tlv;	/* mandatory LLDP chassis TLV */
	//struct ttdp_default_lldp_port_tlv port_tlv;			/* mandatory LLDP port TLV */
	struct ttdp_legacy_lldp_port_tlv legacy_port_tlv;
	struct ttdp_default_lldp_ttl_tlv ttl_tlv;			/* mandatory TTL TLV */
	struct ttdp_hello_tlv hello_tlv;					/* the good stuff */
	struct ttdp_default_lldp_eol_tlv eol_tlv;			/* mandatory LLDP EOL TLV (must be last) */
	/* Implicit Ethernet FCS added by hardware here */
} __attribute__((packed));

/* IEC TC9 WG43 Organizationally Unique ID */
static const uint8_t ttdp_hello_tlv_oui[3] = { 0x20, 0x0E, 0x95 };
/* All TTDP HELLO frames go here */
static const uint8_t ttdp_hello_destination_mac[6] =
	{ 0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E };

/* Timer callbacks */
/* Send in slow mode - 100 ms default */
#define TTDP_PERIODIC_SLOW_SEND_CB_NAME		"ttdp_periodic_send_slow"
#define TTDP_SLOW_INTERVAL_DEFAULT 100

/* Send in fast mode - 15 ms default */
#define TTDP_PERIODIC_FAST_SEND_CB_NAME 	"ttdp_periodic_send_fast"
#define TTDP_FAST_INTERVAL_DEFAULT 15

/* Timeout in slow mode - 130 ms default */
#define TTDP_PERIODIC_SLOW_TIMEOUT_CB_NAME 	"ttdp_periodic_timeout_slow"
#define TTDP_SLOW_TIMEOUT_DEFAULT 130

/* Timeout in fast mode - 45 ms default */
#define TTDP_PERIODIC_FAST_TIMEOUT_CB_NAME	"ttdp_periodic_timeout_fast"
#define TTDP_FAST_TIMEOUT_DEFAULT 45

/* Once we hear from a neighbor, we set our recvstatus to OK on that line.
 * This timeout determines how long we wait (without receiving any frames)
 * before giving up on this neighbor, and setting recvstatus back to ERROR.
 * Default is 1000 ms. Note that this is different than the timeouts above
 * that control whether we consider links as up or down; this one merely
 * controls when we reset a flag in outbound telegrams. */
#define TTDP_PERIODIC_FORGET_PEER_CB_NAME	"ttdp_periodic_forget_peer"
#define TTDP_FORGET_PEER_TIMEOUT_DEFAULT 1000

/* Delay before reporting Ethernet link coming up - 0 ms default */
#define TTDP_PERIODIC_LINK_STATE_DELAY_CB_NAME "ttdp_periodic_link_state_change"
#define TTDP_LINK_STATE_DELAY_UP_DEFAULT 0
/* Delay before reporting Ethernet link going down - 0 ms default */
#define TTDP_LINK_STATE_DELAY_DOWN_DEFAULT 0

/* Callback for socket events */
#define TTDP_SOCKET_CB_NAME "ttdp_socket"


/* 14 for Ethernet header + 4 for VLAN header + the good stuff + EOL TLV */
#define TTDP_HELLO_FRAME_SIZE_MIN \
	(18 + sizeof(struct ttdp_hello_tlv) + sizeof(struct ttdp_default_lldp_eol_tlv))
/* Arbitrary */
#define TTDP_HELLO_FRAME_SIZE_MAX 1024

#define RINGBUF_SIZE 100
static struct ttdp_hello_tlv hello_data_storage[RINGBUF_SIZE] = {};
static int hello_data_storage_next_idx = 0;

static void dump_hello_frame(int i) {
	struct ttdp_hello_tlv* data = &(hello_data_storage[i]);
	const char* antiv_str[] = {"ERR", "NO ", "YES", "UND"};
	teamd_ttdp_log_info("HELLO %.2X:%.2X:%.2X:%.2X:%.2X:%.2X @ %u %c%d %s p:%d inh:%s recv:%s,%s,%s,%s",
		data->srcId.ether_addr_octet[0],
		data->srcId.ether_addr_octet[1],
		data->srcId.ether_addr_octet[2],
		data->srcId.ether_addr_octet[3],
		data->srcId.ether_addr_octet[4],
		data->srcId.ether_addr_octet[5],
		data->lifeSign,
		data->egressLine,
		data->egressDir,
		((data->timeoutSpeed == 1) ? ("SLOW") : ((data->timeoutSpeed == 2) ? ("FAST") : ("UNKN"))),
		data->srcPortId,
		antiv_str[data->inaugInhibition],
		antiv_str[(data->recvStatuses & 0xc0) >> 6],
		antiv_str[(data->recvStatuses & 0x30) >> 4],
		antiv_str[(data->recvStatuses & 0x0c) >> 2],
		antiv_str[(data->recvStatuses & 0x03) >> 0]
		);
}
static void dump_hello_frames() {
	int i = hello_data_storage_next_idx;
	int count = 0;
	teamd_ttdp_log_info("--- BEGIN HELLO FRAME DUMP ---");
	for (; count < RINGBUF_SIZE; count++, i = (i + 1) % RINGBUF_SIZE) {
		dump_hello_frame(i);
	}
	teamd_ttdp_log_info("---- END HELLO FRAME DUMP ----");
}

/* C99 vs POSIX */
size_t strnlen(const char *s, size_t maxlen);
int parse_uuid(const char* src, uint8_t* dest) {
	if (strnlen(src, 38) > 36) { /* must be 36 bytes plus \0 */
		return 1;
	}

	int err = sscanf(src,
		"%02"SCNx8"%02"SCNx8"%02"SCNx8"%02"SCNx8
		"-"
		"%02"SCNx8"%02"SCNx8
		"-"
		"%02"SCNx8"%02"SCNx8
		"-"
		"%02"SCNx8"%02"SCNx8
		"-"
		"%02"SCNx8"%02"SCNx8"%02"SCNx8"%02"SCNx8"%02"SCNx8"%02"SCNx8,
		&(dest[0]), &(dest[1]), &(dest[2]), &(dest[3]),
		&(dest[4]), &(dest[5]),
		&(dest[6]), &(dest[7]),
		&(dest[8]), &(dest[9]),
		&(dest[10]), &(dest[11]), &(dest[12]), &(dest[13]), &(dest[14]), &(dest[15])
		);

	if (err == 16) {
		return 0;
	} else {
		return err;
	}
}

void stringify_uuid(uint8_t* src, char* dest) {
	sprintf(dest,
		"%02"PRIx8"%02"PRIx8"%02"PRIx8"%02"PRIx8
		"-"
		"%02"PRIx8"%02"PRIx8
		"-"
		"%02"PRIx8"%02"PRIx8
		"-"
		"%02"PRIx8"%02"PRIx8
		"-"
		"%02"PRIx8"%02"PRIx8"%02"PRIx8"%02"PRIx8"%02"PRIx8"%02"PRIx8,
		src[0], src[1], src[2], src[3],
		src[4], src[5],
		src[6], src[7],
		src[8], src[9],
		src[10], src[11], src[12], src[13], src[14], src[15]
		);
}

/* stolen from teamd.c */
int parse_hwaddr(const char *hwaddr_str, char **phwaddr,
			unsigned int *plen)
{
	const char *pos = hwaddr_str;
	unsigned int byte_count = 0;
	unsigned int tmp;
	int err;
	char *hwaddr = NULL;
	char *new_hwaddr;
	char *endptr;

	while (true) {
		errno = 0;
		tmp = strtoul(pos, &endptr, 16);
		if (errno != 0 || tmp > 0xFF) {
			err = -EINVAL;
			goto err_out;
		}
		byte_count++;
		new_hwaddr = realloc(hwaddr, sizeof(char) * byte_count);
		if (!new_hwaddr) {
			err = -ENOMEM;
			goto err_out;
		}
		hwaddr = new_hwaddr;
		hwaddr[byte_count - 1] = (char) tmp;
		while (isspace(endptr[0]) && endptr[0] != '\0')
			endptr++;
		if (endptr[0] == ':') {
			pos = endptr + 1;
		} else if (endptr[0] == '\0') {
			break;
		} else {
			err = -EINVAL;
			goto err_out;
		}
	}
	*phwaddr = hwaddr;
	*plen = byte_count;
	return 0;
err_out:
	free(hwaddr);
	return err;
}

static bool get_overall_state(struct lw_ttdp_port_priv *ttdp_ppriv) {
	return (ttdp_ppriv->local_phy_link_up && ttdp_ppriv->local_ttdp_link_up);
}

static void update_neighbor(struct lw_ttdp_port_priv *ttdp_ppriv,
	uint8_t* new_mac, uint8_t* new_uuid, uint32_t new_topocnt) {
	memcpy(ttdp_ppriv->prev_neighbor_uuid, ttdp_ppriv->neighbor_uuid,
		sizeof(ttdp_ppriv->prev_neighbor_uuid));
	memcpy(ttdp_ppriv->prev_neighbor_mac, ttdp_ppriv->neighbor_mac,
		sizeof(ttdp_ppriv->prev_neighbor_mac));
	ttdp_ppriv->prev_neighbor_topocnt = ttdp_ppriv->neighbor_topocnt;
	memcpy(ttdp_ppriv->neighbor_uuid, new_uuid,
		sizeof(ttdp_ppriv->neighbor_uuid));
	memcpy(ttdp_ppriv->neighbor_mac, new_mac,
		sizeof(ttdp_ppriv->neighbor_mac));
	ttdp_ppriv->neighbor_topocnt = new_topocnt;
}

/* also sets it in the parent! */
static void update_neighbor_to_none(struct lw_ttdp_port_priv *ttdp_ppriv) {
	memcpy(ttdp_ppriv->prev_neighbor_uuid, ttdp_ppriv->neighbor_uuid,
		sizeof(ttdp_ppriv->prev_neighbor_uuid));
	memcpy(ttdp_ppriv->prev_neighbor_mac, ttdp_ppriv->neighbor_mac,
		sizeof(ttdp_ppriv->prev_neighbor_mac));
	ttdp_ppriv->prev_neighbor_topocnt = ttdp_ppriv->neighbor_topocnt;

	memset(ttdp_ppriv->neighbor_uuid, 0, sizeof(ttdp_ppriv->neighbor_uuid));
	memset(ttdp_ppriv->neighbor_mac, 0, sizeof(ttdp_ppriv->neighbor_mac));
	ttdp_ppriv->neighbor_topocnt = 0;
	ttdp_ppriv->neighbor_inhibit = TTDP_LOGIC_UNDEFINED;

	teamd_ttdp_log_infox(ttdp_ppriv, "cleared neighbor");
	struct ab* p = ttdp_ppriv->start.common.ctx->runner_priv;

	if (p && ttdp_ppriv->line <= TTDP_MAX_PORTS_PER_TEAM) {
		memcpy(p->neighbors[ttdp_ppriv->line].neighbor_uuid, ttdp_ppriv->neighbor_uuid,
			sizeof(p->neighbors[ttdp_ppriv->line].neighbor_uuid));
		memcpy(p->neighbors[ttdp_ppriv->line].neighbor_mac, ttdp_ppriv->neighbor_mac,
			sizeof(p->neighbors[ttdp_ppriv->line].neighbor_mac));
		p->ifindex_by_line[ttdp_ppriv->line] = ttdp_ppriv->start.common.tdport->ifindex;
		p->neighbors[ttdp_ppriv->line].neighbor_topocount = ttdp_ppriv->neighbor_topocnt;
		p->neighbors[ttdp_ppriv->line].neighbor_inhibition_state = TTDP_LOGIC_UNDEFINED;
	} else {
		/* Should never happen, leaving it here for future 4-line support */
	}
}

static void update_parent_port_status(struct teamd_context *ctx,
	struct lw_ttdp_port_priv *ttdp_ppriv) {
	bool state = get_overall_state(ttdp_ppriv);
	struct ab* ab = ctx->runner_priv;
	uint8_t new_state = (state ? 2 : 1);
	bool heard_prev = ab->lines_heard[ttdp_ppriv->line];
	if ((heard_prev != ttdp_ppriv->heard) || (ab->port_statuses[ttdp_ppriv->line] != new_state)) {
		ab->lines_heard[ttdp_ppriv->line] = ttdp_ppriv->heard;
		ab->port_statuses[ttdp_ppriv->line] = new_state;
		ab->port_statuses_b =
			(ab->port_statuses[0] << 6) |
			(ab->port_statuses[1] << 4) |
			(ab->port_statuses[2] << 2) |
			(ab->port_statuses[3] << 0);
		teamd_ttdp_log_dbgx(ttdp_ppriv, "setting line status to %d", state);
		if (ab->line_state_update_func) {
			ab->line_state_update_func(ctx, ctx->runner_priv);
		}
	}
}

static void force_parent_port_status(struct teamd_context *ctx,
	struct lw_ttdp_port_priv *ttdp_ppriv, int state) {
	struct ab* ab = ctx->runner_priv;
	if (ab->port_statuses[ttdp_ppriv->line] != state) {
		ab->port_statuses[ttdp_ppriv->line] = state;
		ab->port_statuses_b =
			(ab->port_statuses[0] << 6) |
			(ab->port_statuses[1] << 4) |
			(ab->port_statuses[2] << 2) |
			(ab->port_statuses[3] << 0);
		teamd_ttdp_log_dbgx(ttdp_ppriv, "forcing line status to %d", state);
		if (ab->line_state_update_func) {
			ab->line_state_update_func(ctx, ctx->runner_priv);
		}
	}
}


static int lw_ttdp_load_options(struct teamd_context *ctx,
			      struct teamd_port *tdport,
			      struct lw_ttdp_port_priv *ttdp_ppriv) {
	teamd_ttdp_log_dbgx(ttdp_ppriv, "ttdp lw: lw_ttdp_load_options");
	struct teamd_config_path_cookie *cpcookie = ttdp_ppriv->start.common.cpcookie;

	int tmp;
	bool tmpb;
	const char* tmpstr;
	int err;
	if (ctx->runner && ctx->runner->name && (strncmp("ttdp", ctx->runner->name, 5) != 0)) {
		teamd_log_err("This linkwatcher requires the \"ttdp\" runner. Aborting.");
		return 1;
	}
	struct ab* ab = ctx->runner_priv;

	if (ab == NULL) {
		teamd_log_err("Configuration error");
		return 1;
	}

	err = teamd_config_int_get(ctx, &tmp, "@.initial_mode", cpcookie);
	if (err) {
		teamd_log_warn("Failed to get initial_mode, defaulting to 1 (slow)");
		tmp = 1;
	} else {
		teamd_ttdp_log_dbgx(ttdp_ppriv, "ttdp initial_mode %d", tmp);
	}
	ttdp_ppriv->initial_mode = tmp;

	err = teamd_config_bool_get(ctx, &tmpb, "@.fast_failed_recovery_mode", cpcookie);
	if (err) {
		teamd_log_warn("Failed to get fast_failed_recovery_mode, defaulting to off");
		tmpb = false;
	} else {
		teamd_ttdp_log_dbgx(ttdp_ppriv, "ttdp fast_failed_recovery_mode %d", tmpb);
	}
	ttdp_ppriv->fast_failed_recovery_mode = tmpb;

	err = teamd_config_int_get(ctx, &tmp, "@.slow_interval", cpcookie);
	if (err) {
		teamd_log_warn("Failed to get slow_interval, defaulting to %d ms", TTDP_SLOW_INTERVAL_DEFAULT);
		tmp = TTDP_SLOW_INTERVAL_DEFAULT;
	} else {
		teamd_ttdp_log_dbgx(ttdp_ppriv, "ttdp slow_interval %d", tmp);
	}
	ms_to_timespec(&(ttdp_ppriv->slow_interval), tmp);

	err = teamd_config_int_get(ctx, &tmp, "@.fast_interval", cpcookie);
	if (err) {
		teamd_log_warn("Failed to get fast_interval, defaulting to %d ms", TTDP_FAST_INTERVAL_DEFAULT);
		tmp = TTDP_FAST_INTERVAL_DEFAULT;
	} else {
		teamd_ttdp_log_dbgx(ttdp_ppriv, "ttdp fast_interval %d", tmp);
	}
	ms_to_timespec(&(ttdp_ppriv->fast_interval), tmp);

	err = teamd_config_int_get(ctx, &tmp, "@.slow_timeout", cpcookie);
	if (err) {
		teamd_log_warn("Failed to get slow_timeout, defaulting to %d ms", TTDP_SLOW_TIMEOUT_DEFAULT);
		tmp = TTDP_SLOW_TIMEOUT_DEFAULT;
	} else {
		teamd_ttdp_log_dbgx(ttdp_ppriv, "ttdp slow_timeout %d", tmp);
	}
	ms_to_timespec(&(ttdp_ppriv->slow_timeout), tmp);

	err = teamd_config_int_get(ctx, &tmp, "@.fast_timeout", cpcookie);
	if (err) {
		teamd_log_warn("Failed to get fast_timeout, defaulting to %d ms", TTDP_FAST_TIMEOUT_DEFAULT);
		tmp = TTDP_FAST_TIMEOUT_DEFAULT;
	} else {
		teamd_ttdp_log_dbgx(ttdp_ppriv, "ttdp fast_timeout %d", tmp);
	}
	ms_to_timespec(&(ttdp_ppriv->fast_timeout), tmp);

	err = teamd_config_int_get(ctx, &tmp, "@.forget_peer_timeout", cpcookie);
	if (err) {
		teamd_log_warn("Failed to get forget_peer_timeout, defaulting to %d ms",
			TTDP_FORGET_PEER_TIMEOUT_DEFAULT);
		tmp = TTDP_FORGET_PEER_TIMEOUT_DEFAULT;
	} else {
		teamd_ttdp_log_dbgx(ttdp_ppriv, "ttdp forget_peer_timeout %d", tmp);
	}
	ms_to_timespec(&(ttdp_ppriv->forget_peer), tmp);

	err = teamd_config_bool_get(ctx, &tmpb, "@.immediate_timer_start_mode", cpcookie);
	if (err) {
		teamd_log_warn("Failed to get immediate_timer_start_mode, defaulting to off");
		tmpb = false;
	} else {
		teamd_ttdp_log_dbgx(ttdp_ppriv, "ttdp immediate_timer_start_mode %d", tmpb);
	}
	ttdp_ppriv->immediate_timer_start_mode = tmpb;


	err = teamd_config_int_get(ctx, &tmp, "@.link_state_delay_up", cpcookie);
	if (err) {
		teamd_log_warn("Failed to get link_state_delay_up, defaulting to %d ms", TTDP_LINK_STATE_DELAY_UP_DEFAULT);
		tmp = TTDP_LINK_STATE_DELAY_UP_DEFAULT;
	} else {
		teamd_ttdp_log_dbgx(ttdp_ppriv, "ttdp link_state_delay_up %d", tmp);
	}
	ms_to_timespec(&(ttdp_ppriv->link_state_delay_up), tmp);

	err = teamd_config_int_get(ctx, &tmp, "@.link_state_delay_down", cpcookie);
	if (err) {
		teamd_log_warn("Failed to get link_state_delay_down, defaulting to %d ms", TTDP_LINK_STATE_DELAY_DOWN_DEFAULT);
		tmp = TTDP_LINK_STATE_DELAY_DOWN_DEFAULT;
	} else {
		teamd_ttdp_log_dbgx(ttdp_ppriv, "ttdp link_state_delay_down %d", tmp);
	}
	ms_to_timespec(&(ttdp_ppriv->link_state_delay_down), tmp);

	err = teamd_config_string_get(ctx, &tmpstr, "@.local_uuid", cpcookie);
	if (err) {
		struct ab* ab = ctx->runner_priv;
		if (ab && ab->local_uuid_set) {
			memcpy(ttdp_ppriv->local_uuid, ab->local_uuid, sizeof(ttdp_ppriv->local_uuid));
			memcpy(ttdp_ppriv->local_uuid_str, ab->local_uuid_str, sizeof(ttdp_ppriv->local_uuid_str));
		} else {
			teamd_log_err("TTDP: Error, failed to read UUID string in linkwatcher and runner");
			return 1;
		}
	} else {
		err = parse_uuid(tmpstr, ttdp_ppriv->local_uuid);
		if (err) {
			teamd_log_err("TTDP: Error, failed to parse UUID string: %d", err);
			return 1;
		}
	}

	err = teamd_config_int_get(ctx, &tmp, "@.direction", cpcookie);
	if (err) {
		struct ab* ab = ctx->runner_priv;
		if (ab && (ab->direction == 1 || ab->direction == 2)) {
			teamd_ttdp_log_infox(ttdp_ppriv, "Watcher direction not specified - using runner direction %d", ab->direction);
			ttdp_ppriv->direction = ab->direction;
		} else {
			teamd_log_err("TTDP: Error, failed to read direction");
			return 1;
		}
	} else {
		if (tmp != 1 && tmp != 2) {
			teamd_log_err("TTDP: Error, invalid direction - use 1 or 2");
			return 1;
		}
		ttdp_ppriv->direction = tmp;
	}

	err = teamd_config_string_get(ctx, &tmpstr, "@.line", cpcookie);
	if (err) {
		teamd_log_err("TTDP: Error, failed to read line");
		return 1;
	} else {
		if (tmpstr[1] != 0 || (((tmpstr[0] & 0x5f) != 0x41) && ((tmpstr[0] & 0x5f) != 0x42))) {
			teamd_log_err("TTDP: Error, line must be 'A' or 'B', got %c %X", tmpstr[0], (tmpstr[0] & 0x5f));
			return 1;
		}
		ttdp_ppriv->line = (tmpstr[0] & 0x5f) - 0x41;
	}

	err = teamd_config_string_get(ctx, &tmpstr, "@.identity_hwaddr", cpcookie);
	if (err) {
		struct ab* ab = ctx->runner_priv;
		if (ab && ab->identity_hwaddr_set) {
			teamd_ttdp_log_infox(ttdp_ppriv, "Identity hwaddr not given - using runner configuration instead");
			memcpy(ttdp_ppriv->identity_hwaddr, ab->identity_hwaddr, sizeof(ttdp_ppriv->identity_hwaddr));
			memcpy(ttdp_ppriv->identity_hwaddr_str, ab->identity_hwaddr_str, sizeof(ttdp_ppriv->identity_hwaddr_str));
			ttdp_ppriv->identity_hwaddr_ptr = ttdp_ppriv->identity_hwaddr;
		} else {
			teamd_ttdp_log_infox(ttdp_ppriv, "Identity hwaddr not given - using team device hwaddr instead");
			ttdp_ppriv->identity_hwaddr_ptr = (ttdp_ppriv->start.common.ctx->hwaddr);
		}
	} else {
		char* tempmac;
		unsigned int templen = 0;
		if (parse_hwaddr(tmpstr, &tempmac, &templen) != 0) {
			teamd_log_err("TTDP: Error, could not parse identity hwaddr %s, aborting", tmpstr);
			return 1;
		} else if (templen != ctx->hwaddr_len) {
			teamd_log_err("TTDP: Error, identity hwaddr has incorrect length %d, team device has %d",
				templen, ctx->hwaddr_len);
			free(tempmac);
			return 1;
		} else {
			teamd_ttdp_log_infox(ttdp_ppriv, "Identity hwaddr set.");
			memcpy(ttdp_ppriv->identity_hwaddr, tempmac, templen);
			memcpy(ttdp_ppriv->identity_hwaddr_str, tmpstr, sizeof(ttdp_ppriv->identity_hwaddr_str));
			ttdp_ppriv->identity_hwaddr_ptr = ttdp_ppriv->identity_hwaddr;
			free(tempmac);
		}
	}

	err = teamd_config_bool_get(ctx, &tmpb, "@.strict_peer_recv_status", cpcookie);
	if (err) {
		teamd_log_warn("Failed to get strict_peer_recv_status, defaulting to on");
		tmpb = true;
	} else {
		teamd_ttdp_log_dbgx(ttdp_ppriv, "ttdp strict_peer_recv_status %d", tmpb);
	}
	ttdp_ppriv->strict_peer_recv_status = tmpb;

	/* copy chassis address from runner configuration */
	memcpy(ttdp_ppriv->chassis_hwaddr, ab->chassis_hwaddr, sizeof (ttdp_ppriv->chassis_hwaddr));

	/* copy vendor info from runner configuration and ensure it is 0-terminated */
	memcpy(ttdp_ppriv->vendor_info, ab->vendor_info, sizeof (ttdp_ppriv->vendor_info));
	ttdp_ppriv->vendor_info[sizeof(ttdp_ppriv->vendor_info)-1] = 0;

	/* check that timer intervals are sane */
	if (timespec_is_zero(&ttdp_ppriv->fast_interval) || timespec_is_zero(&ttdp_ppriv->slow_interval)) {
		teamd_log_err("TTDP: Error, timer intervals not sane");
		return 1;
	}

	/* check that timeouts are greater than timer intervals */
	if ((timespec_to_ms(&ttdp_ppriv->slow_timeout) <= timespec_to_ms(&ttdp_ppriv->slow_interval)) ||
		(timespec_to_ms(&ttdp_ppriv->fast_timeout) <= timespec_to_ms(&ttdp_ppriv->fast_interval))) {
		teamd_log_err("TTDP: Error, timeouts must be greater than intervals");
		return 1;
	}

	/* check that timer intervals are ordered correctly  */
	if (timespec_to_ms(&ttdp_ppriv->slow_interval) <= timespec_to_ms(&ttdp_ppriv->fast_interval)) {
		teamd_log_warn("TTDP: Warning, SLOW interval is not greater than FAST interval. Misconfiguration?");
	}

	/* check that timeouts are ordered correctly */
	if (timespec_to_ms(&ttdp_ppriv->slow_timeout) <= timespec_to_ms(&ttdp_ppriv->fast_timeout)) {
		teamd_log_warn("TTDP: Warning, SLOW timeout is not greater than FAST timeout. Misconfiguration?");
	}

	return 0;
}

static int update_overall_state(struct teamd_context *ctx, void* priv){
	struct lw_common_port_priv *common_ppriv = priv;
	struct lw_ttdp_port_priv* ttdp_ppriv = (struct lw_ttdp_port_priv*)priv;
	/*struct ab* ab = ctx->runner_priv;*/

	bool overall_state = (ttdp_ppriv->local_ttdp_link_up
		&& ttdp_ppriv->local_phy_link_up && ttdp_ppriv->heard
		/*&& (ab->aggregate_status != TTDP_AGG_STATE_FIXED_END)*/);
	teamd_ttdp_log_infox(ttdp_ppriv, "state change to -> %s", (overall_state ? "UP" : "DOWN"));
	return teamd_link_watch_check_link_up(ctx, common_ppriv->tdport, priv, overall_state);
}

static int lw_ttdp_sock_open(struct lw_ttdp_port_priv* ttdp_ppriv) {
	teamd_ttdp_log_dbgx(ttdp_ppriv, "ttdp lw: ttdp_sock_open");
	int err;

	err = teamd_packet_sock_open_type(SOCK_RAW, &ttdp_ppriv->start.psr.sock,
					  ttdp_ppriv->start.common.tdport->ifindex,
					  htons(ETH_P_ALL), &ttdp_hello_fprog, NULL);

	teamd_ttdp_log_dbgx(ttdp_ppriv, "Socket open result %d", err);

	/* Enter promiscuous mode */
	teamd_ttdp_log_infox(ttdp_ppriv, "Enabling promiscuous mode for interface #%d",
		ttdp_ppriv->start.common.tdport->ifindex);
	struct packet_mreq mreq = {
		.mr_ifindex = ttdp_ppriv->start.common.tdport->ifindex,
		.mr_type = PACKET_MR_PROMISC,
		.mr_alen = 0,
		.mr_address = {0}
	};
	err = setsockopt(ttdp_ppriv->start.psr.sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq));

	teamd_ttdp_log_dbgx(ttdp_ppriv, "packet sock open: %d flen %d\n", err, ttdp_hello_fprog.len);
	return err;
}

static void lw_ttdp_sock_close(struct lw_ttdp_port_priv *ttdp_ppriv)
{
	teamd_ttdp_log_dbgx(ttdp_ppriv, "ttdp lw: lw_ttdp_sock_close");
	/* Leave promiscuous mode */
	teamd_ttdp_log_infox(ttdp_ppriv, "Disabling promiscuous mode for interface #%d",
		ttdp_ppriv->start.common.tdport->ifindex);

		struct packet_mreq mreq = {
		.mr_ifindex = ttdp_ppriv->start.common.tdport->ifindex,
		.mr_type = PACKET_MR_PROMISC,
		.mr_alen = 0,
		.mr_address = {0}
	};
	setsockopt(ttdp_ppriv->start.psr.sock, SOL_PACKET, PACKET_DROP_MEMBERSHIP, &mreq, sizeof(mreq));

	close(ttdp_ppriv->start.psr.sock);
}

static int __get_port_curr_hwaddr(struct lw_ttdp_port_priv *priv,
				  struct sockaddr_ll *addr, size_t expected_len)
{
	struct team_ifinfo *ifinfo = priv->start.common.tdport->team_ifinfo;
	size_t port_hwaddr_len = team_get_ifinfo_hwaddr_len(ifinfo);
	char *port_hwaddr = team_get_ifinfo_hwaddr(ifinfo);
	int err;

	err = teamd_getsockname_hwaddr(priv->start.psr.sock, addr, expected_len);
	if (err)
		return err;
	if ((addr->sll_halen != port_hwaddr_len) ||
	    (expected_len && expected_len != port_hwaddr_len)) {
		teamd_log_err("Unexpected length of hw address.");
		return -ENOTSUP;
	}
	memcpy(addr->sll_addr, port_hwaddr, addr->sll_halen);
	return 0;
}

static void construct_default_frame(struct ab* parent, struct lw_ttdp_port_priv *ttdp_ppriv,
	struct ttdp_default_hello_frame* out) {

	struct sockaddr_ll source_addr;

	if (__get_port_curr_hwaddr(ttdp_ppriv, &source_addr, 6) != 0) {
		/* FIXME ERR */
		teamd_log_warn("construct_default_frame: could not get source MAC, aborting");
		return;
	}



	/* Ethernet header & VLAN */
	memcpy(&(out->frame_header.ether_header.ether_dhost), ttdp_hello_destination_mac, 6);
	memcpy(&(out->frame_header.ether_header.ether_shost), source_addr.sll_addr, 6);
	out->frame_header.ether_header.ether_type = htons(0x8100);
	out->frame_header.vlan_tags = htons(0xE1EC);
	out->frame_header.enc_ethertype = htons(0x88CC);

	/* Chassis TLV */
	out->chassis_tlv.header.header = TTDP_MAKE_TLV_TYPE_LEN(1, 7);
	out->chassis_tlv.chassisIdSubtype = 0x04;
	memcpy(&(out->chassis_tlv.chassisId), ttdp_ppriv->chassis_hwaddr, sizeof(out->chassis_tlv.chassisId));

	/* Port TLV */
	//out->port_tlv.header.header = TTDP_MAKE_TLV_TYPE_LEN(2, 2);
	//out->port_tlv.portIdSubtype = 0x06;
	///* FIXME */out->port_tlv.portId = 1;

	/* Legacy port TLV */
	out->legacy_port_tlv.header.header = TTDP_MAKE_TLV_TYPE_LEN(2, 7);
	out->legacy_port_tlv.portIdSubtype = 0x03;
	memcpy(&(out->legacy_port_tlv.mac), source_addr.sll_addr, 6);

	/* TTL TLV */
	out->ttl_tlv.header.header = TTDP_MAKE_TLV_TYPE_LEN(3, 2);
	out->ttl_tlv.ttl = htons(120);
	/* HELLO TLV */
	out->hello_tlv.header.header = TTDP_MAKE_TLV_TYPE_LEN(127, 86);

	memcpy(&(out->hello_tlv.oui), ttdp_hello_tlv_oui, 3);
	out->hello_tlv.ttdpSubtype = 0x01;
	out->hello_tlv.tlvCS = 0; /* Calculated in lw_ttdp_send() / lw_ttdp_send_fast() */
	out->hello_tlv.version = htonl(0x01000000);
	out->hello_tlv.lifeSign = htonl((ttdp_ppriv->lifesign)++);
	out->hello_tlv.etbTopoCnt = parent->etb_topo_counter;

	/* We must ensure that the vendor string is zero terminated and -padded */
	memset(out->hello_tlv.vendor, 0, sizeof(out->hello_tlv.vendor));
	memcpy(out->hello_tlv.vendor, ttdp_ppriv->vendor_info, strnlen(ttdp_ppriv->vendor_info,
		sizeof(ttdp_ppriv->vendor_info)));
	out->hello_tlv.vendor[sizeof(out->hello_tlv.vendor)-1] = 0;

	out->hello_tlv.recvStatuses = parent->port_statuses_b;
	out->hello_tlv.timeoutSpeed = 0; /* Set in lw_ttdp_send() / lw_ttdp_send_fast() */
	//memcpy(&(out->hello_tlv.srcId), source_addr.sll_addr, 6);
	/* FIXME check sizes of these */
	memcpy(&(out->hello_tlv.srcId), ttdp_ppriv->identity_hwaddr, 6);

	out->hello_tlv.srcPortId = (ttdp_ppriv->start.common.tdport->ifindex + 1),
	out->hello_tlv.egressLine = 0x41 + ttdp_ppriv->line;
	out->hello_tlv.egressDir = ttdp_ppriv->direction;

	uint8_t inhibit_any = (parent->inhibition_flag_local | parent->inhibition_flag_any);
	out->hello_tlv.inaugInhibition = inhibit_any;// | parent->inhibition_flag_remote);
	/* fix the "ANTIVALENT" insanity */
	if (out->hello_tlv.inaugInhibition != TTDP_LOGIC_FALSE)
		out->hello_tlv.inaugInhibition = TTDP_LOGIC_TRUE;
	memcpy(&(out->hello_tlv.remoteId), ttdp_ppriv->neighbor_mac, 6);
	out->hello_tlv.reserved2 = 0;
	memcpy(&(out->hello_tlv.cstUUid), ttdp_ppriv->local_uuid, 16);

	/* EOL TLV */
	out->eol_tlv.header.header = TTDP_MAKE_TLV_TYPE_LEN(0, 0);

}

static void ttdp_insert_checksum(struct ttdp_hello_tlv* tlv) {
/* Calculate HELLO TVL checksum over TLV payload "from first TLV word
	 * after the checksum to the last TLV word, both included" */
	size_t checksummed_length =
		((uint8_t*)&(tlv->cstUUid)+sizeof(tlv->cstUUid)) - (uint8_t*)&(tlv->version);
	tlv->tlvCS = frame_checksum((uint8_t*)&(tlv->version), checksummed_length, 0, 1);
}

static int ttdp_verify_checksum(struct ttdp_hello_tlv* tlv, struct lw_ttdp_port_priv *ttdp_ppriv) {
	size_t checksummed_length =
		((uint8_t*)&(tlv->cstUUid)+sizeof(tlv->cstUUid)) - (uint8_t*)&(tlv->version);
	uint16_t calc = frame_checksum((uint8_t*)&(tlv->version), checksummed_length, 0, 0);
	if (calc != tlv->tlvCS) {
		teamd_ttdp_log_infox(ttdp_ppriv, "HELLO TLV checksum mismatch: got %04hX, expected %04hX", tlv->tlvCS, calc);
		return 1;
	}

	/* FIXME move this out? */
	if ((ntohl(tlv->version) & 0xFF000000) != 0x01000000) {
		teamd_ttdp_log_infox(ttdp_ppriv, "HELLO TLV version mismatch: got %08" PRIX32 ", expected %08"
			PRIX32 " (only first byte matters)",
			(ntohl(tlv->version)), 0x01000000);
		return 2;
	}

	return 0;
}

static int lw_ttdp_send_fast(struct teamd_context *ctx, int events, void *priv) {
	//fprintf(stderr, "ttdp lw: lw_ttdp_send_fast\n");
	struct lw_ttdp_port_priv* ttdp_ppriv = (struct lw_ttdp_port_priv*)priv;

	struct ttdp_default_hello_frame frame;
	construct_default_frame(ctx->runner_priv, ttdp_ppriv, &frame);
	frame.hello_tlv.timeoutSpeed = 2; /* fast */

	struct sockaddr_ll ll_dest;
	memset(&ll_dest, 0, sizeof(ll_dest));
	/* Get the format right first */
	__get_port_curr_hwaddr(ttdp_ppriv, &ll_dest, 0);
	memcpy(&(ll_dest.sll_addr), ttdp_hello_destination_mac, 6);
	ll_dest.sll_family = AF_PACKET;
	ll_dest.sll_protocol = ntohs(0x8100);

	ttdp_insert_checksum(&(frame.hello_tlv));

	/* Send TTDP HELLO frame here */
	if (ttdp_ppriv->silent == true)
		return 0;

	int err = teamd_sendto(ttdp_ppriv->start.psr.sock, &frame, sizeof(frame),
	 		    0, (struct sockaddr *) &ll_dest,
	 		    sizeof(ll_dest));
	//fprintf(stderr, "ttdp lw: lw_ttdp_send result %d\n", err);
	return err;
}

static int lw_ttdp_send(struct teamd_context *ctx, int events, void *priv) {
	//fprintf(stderr, "ttdp lw: lw_ttdp_send_fast\n");
	struct lw_ttdp_port_priv* ttdp_ppriv = (struct lw_ttdp_port_priv*)priv;

	/* Construct TTDP HELLO frame */
	struct ttdp_default_hello_frame frame;
	construct_default_frame(ctx->runner_priv, ttdp_ppriv, &frame);
	frame.hello_tlv.timeoutSpeed = 1; /* slow */

	struct sockaddr_ll ll_dest;
	memset(&ll_dest, 0, sizeof(ll_dest));
	/* Get the format right first */
	__get_port_curr_hwaddr(ttdp_ppriv, &ll_dest, 0);
	memcpy(&(ll_dest.sll_addr), ttdp_hello_destination_mac, 6);
	ll_dest.sll_family = AF_PACKET;
	ll_dest.sll_protocol = ntohs(0x8100);

	ttdp_insert_checksum(&(frame.hello_tlv));

	if (ttdp_ppriv->silent == true)
		return 0;

	/* Send TTDP HELLO frame here */
	int err = teamd_sendto(ttdp_ppriv->start.psr.sock, &frame, sizeof(frame),
	 		    0, (struct sockaddr *) &ll_dest,
	 		    sizeof(ll_dest));
	//fprintf(stderr, "ttdp lw: lw_ttdp_send result %d\n", err);
	return err;
}

static void ttdp_start_fast_send_timer(struct teamd_context *ctx,
	struct lw_ttdp_port_priv *ttdp_ppriv);
static void ttdp_stop_fast_send_timer(struct teamd_context *ctx,
	struct lw_ttdp_port_priv *ttdp_ppriv);
static void ttdp_start_slow_send_timer(struct teamd_context *ctx,
	struct lw_ttdp_port_priv *ttdp_ppriv);
static void ttdp_stop_slow_send_timer(struct teamd_context *ctx,
	struct lw_ttdp_port_priv *ttdp_ppriv);

static inline void ttdp_start_fast_send_timer(struct teamd_context *ctx,
	struct lw_ttdp_port_priv *ttdp_ppriv) {
	if (ttdp_ppriv->local_slow_timer_started) {
		ttdp_stop_slow_send_timer(ctx, ttdp_ppriv);
	}
	teamd_ttdp_log_infox(ttdp_ppriv, "switched to FAST sending mode");
	if (!ttdp_ppriv->local_fast_timer_started) {
		teamd_loop_callback_timer_add_set(
			ctx,
			TTDP_PERIODIC_FAST_SEND_CB_NAME,
			ttdp_ppriv,
			lw_ttdp_send_fast,
			&(ttdp_ppriv->fast_interval),
			(ttdp_ppriv->initial_fast_interval));
	}
	teamd_loop_callback_enable(ctx, TTDP_PERIODIC_FAST_SEND_CB_NAME, ttdp_ppriv);
	ttdp_ppriv->local_fast_timer_started = true;
}

static inline void ttdp_stop_fast_send_timer(struct teamd_context *ctx,
	struct lw_ttdp_port_priv *ttdp_ppriv) {
	teamd_loop_callback_disable(ctx, TTDP_PERIODIC_FAST_SEND_CB_NAME, ttdp_ppriv);
	teamd_loop_callback_del(ctx, TTDP_PERIODIC_FAST_SEND_CB_NAME, ttdp_ppriv);
	ttdp_ppriv->local_fast_timer_started = false;
}

static inline void ttdp_start_slow_send_timer(struct teamd_context *ctx,
	struct lw_ttdp_port_priv *ttdp_ppriv) {
	if (ttdp_ppriv->local_fast_timer_started) {
		ttdp_stop_fast_send_timer(ctx, ttdp_ppriv);
	}
	teamd_ttdp_log_infox(ttdp_ppriv, "switched to SLOW sending mode");
	if (!ttdp_ppriv->local_slow_timer_started) {
		teamd_loop_callback_timer_add_set(
			ctx,
			TTDP_PERIODIC_SLOW_SEND_CB_NAME,
			ttdp_ppriv,
			lw_ttdp_send,
			&(ttdp_ppriv->slow_interval),
			(ttdp_ppriv->initial_slow_interval));
	}
	teamd_loop_callback_enable(ctx, TTDP_PERIODIC_SLOW_SEND_CB_NAME, ttdp_ppriv);
	ttdp_ppriv->local_slow_timer_started = true;
}

static inline void ttdp_stop_slow_send_timer(struct teamd_context *ctx,
	struct lw_ttdp_port_priv *ttdp_ppriv) {
	teamd_loop_callback_disable(ctx, TTDP_PERIODIC_SLOW_SEND_CB_NAME, ttdp_ppriv);
	teamd_loop_callback_del(ctx, TTDP_PERIODIC_SLOW_SEND_CB_NAME, ttdp_ppriv);
	ttdp_ppriv->local_slow_timer_started = false;
}



/* Called SLOW_TIMEOUT (130 ms) after last receipt of a HELLO packet */
static int lw_ttdp_enter_recovery_mode(struct teamd_context *ctx, int events, void *priv) {
	/* Start fast sending mode and start fast timeout timer */
	struct lw_ttdp_port_priv *ttdp_ppriv = (struct lw_ttdp_port_priv *)priv;
	teamd_ttdp_log_dbgx(ttdp_ppriv, "ttdp lw: tw_ttdp_enter_recovery_mode");
	teamd_ttdp_log_infox(ttdp_ppriv, "Entered recovery mode - logical link state pending...");

	//teamd_loop_callback_enable(ctx, TTDP_PERIODIC_FAST_SEND_CB_NAME, priv);
	ttdp_start_fast_send_timer(ctx, ttdp_ppriv);


	ttdp_ppriv->local_recovery_mode = 1;

	/* Disable this callback so we don't call it while in recovery mode */
	teamd_loop_callback_disable(ctx, TTDP_PERIODIC_SLOW_TIMEOUT_CB_NAME, priv);

	/* Reset & start the "fast timeout" timer */
	teamd_loop_callback_timer_set(ctx,
		TTDP_PERIODIC_FAST_TIMEOUT_CB_NAME,
		priv,
		&(ttdp_ppriv->fast_timeout),
		&(ttdp_ppriv->fast_timeout));
	teamd_loop_callback_enable(ctx, TTDP_PERIODIC_FAST_TIMEOUT_CB_NAME, priv);

	return 0;
}
/* Called FAST_TIMEOUT (45 ms) after entering recovery mode */
static int lw_ttdp_fail_recovery_mode(struct teamd_context *ctx, int events, void *priv) {
	//struct lw_common_port_priv *common_ppriv = priv;
	struct lw_ttdp_port_priv* ttdp_ppriv = (struct lw_ttdp_port_priv*)priv;
	struct ab *ab = ctx->runner_priv;

	teamd_ttdp_log_dbgx(ttdp_ppriv, "ttdp lw: lw_ttdp_fail_recovery_mode in mode %d", ttdp_ppriv->local_recovery_mode);
	teamd_ttdp_log_infox(ttdp_ppriv, "Failed recovery mode - logical link state is now DOWN");
	/* Set port status to "not good" and stop the timeout timers
	 * since we're now in recovery mode and will just keep sending
	 * frames until we get a reply */

	/* set port status */
	ttdp_ppriv->local_ttdp_link_up = false;

	/* consider neighbor down */
	ab->neighbor_lines[ttdp_ppriv->line] = '-';
	update_parent_port_status(ctx, ttdp_ppriv);
	update_neighbor_to_none(ttdp_ppriv);
	update_overall_state(ctx, priv);
	teamd_event_port_changed(ctx, ttdp_ppriv->start.common.tdport);

	teamd_loop_callback_disable(ctx, TTDP_PERIODIC_SLOW_TIMEOUT_CB_NAME, priv);
	teamd_loop_callback_disable(ctx, TTDP_PERIODIC_FAST_TIMEOUT_CB_NAME, priv);

	/* resume sending in SLOW mode by default; if configured, stay in
	 * FAST mode otherwise */
	if (ttdp_ppriv->fast_failed_recovery_mode) {
		ttdp_start_fast_send_timer(ctx, ttdp_ppriv);
	} else {
		ttdp_start_slow_send_timer(ctx, ttdp_ppriv);
	}

	return 0;
}

static void fixup_parse_ttdp_frame(struct ttdp_hello_tlv* data) {
	data->tlvCS = ntohs(data->tlvCS);
	/* ??? data->etbTopoCnt = ntohl(data->etbTopoCnt); */
	//data->etbTopoCnt = data->etbTopoCnt;
	data->lifeSign = ntohl(data->lifeSign);
	data->version = ntohl(data->version);
}

static void detect_ttdp_line_mismatch(struct ttdp_hello_tlv* out, struct lw_ttdp_port_priv* ttdp_ppriv,
	struct teamd_context *ctx) {
	struct ab* p = (struct ab*)ctx->runner_priv;
	/* egressLine is 'A', 'B', 'C', 'D' or '-'. Our local line is 0 for 'A', or 1 for 'B'.
	 * '-' is assumed to mean "not supported". */
	if (out->egressLine != '-') {
		p->neighbor_lines[ttdp_ppriv->line] = out->egressLine;
		if (out->egressLine - 'A' != ttdp_ppriv->line) {
			p->crossed_lines_detected = true;
		}
	}
}

static void detect_ttdp_mixed_consist_orientation(struct ttdp_hello_tlv* out,
	struct lw_ttdp_port_priv* ttdp_ppriv, struct teamd_context *ctx) {
	struct ab* p = (struct ab*)ctx->runner_priv;
	/* Check if our neighbor is another node in our own consist, and is not connected
	 * 1-2 or 2-1. Nodes in the same consist should not have different orientations! */
	/* egressDir is 1 or 2. Our local direction uses the same format. */
	if (memcmp(out->cstUUid, ttdp_ppriv->local_uuid, sizeof(out->cstUUid)) == 0) {
		if (out->egressDir == ttdp_ppriv->direction) {
			p->mixed_consist_orientation_detected = true;
		}
	}
}

static int parse_ttdp_frame(const uint8_t* frame, size_t frame_len, struct ttdp_hello_tlv* out,
	struct lw_ttdp_port_priv* ttdp_ppriv, struct teamd_context *ctx) {

	if (frame_len < TTDP_HELLO_FRAME_SIZE_MIN) {
		teamd_ttdp_log_infox(ttdp_ppriv, "TTDP HELLO frame is short - got %zd, wanted %zd",
			frame_len, TTDP_HELLO_FRAME_SIZE_MIN);
		return -1;
	}

	/* VLAN tags removed here for some reason or other, so the first TLV starts at 14 */
	size_t offset = 14; /* start of first TVL header */
	int tlv_idx;
	for (tlv_idx = 0; tlv_idx < 10; ++tlv_idx) {
		if (offset >= frame_len) {
			teamd_ttdp_log_dbgx(ttdp_ppriv, "Malformed packet, offset %zu would be outside length %zu", offset, frame_len);
			return 1;
		}
		uint16_t tlv_header = (frame[offset] << 8) | frame[offset+1];
		uint8_t tlv_type = (tlv_header & 0xFE00) >> 9;
		uint8_t tlv_len = tlv_header & 0x01FF;
		//fprintf(stderr, "parsing TLV header %0.4X type %d len %d\n", tlv_header, tlv_type, tlv_len);

		switch (tlv_type) {
			case 127:
				//fprintf(stderr, "Specific TLV #%d len %d\n", tlv_idx, tlv_len);
				/* Check that the OUI matches and do a final size check */
				/* we need at least 2+3 bytes (header+OUI) left in the frame to read the OUI.
				 * Test this first, then check the OUI, then the size of the TLV */
				if (((offset + 5) <= frame_len) && (memcmp(frame+offset+2, ttdp_hello_tlv_oui, 3) == 0)
					&& ((offset + sizeof(struct ttdp_hello_tlv)) < frame_len)) {
					//fprintf(stderr, "HELLO!\n");
					memcpy(out, frame+offset, sizeof(struct ttdp_hello_tlv));
					/* verify frame CRC before byte order conversion */
					if (ttdp_verify_checksum(out, ttdp_ppriv) != 0) {
						(ttdp_ppriv->checksum_fail_counter)++;
						return 1;
					}
					fixup_parse_ttdp_frame(out);
					detect_ttdp_line_mismatch(out, ttdp_ppriv, ctx);
					detect_ttdp_mixed_consist_orientation(out, ttdp_ppriv, ctx);
					return 0;
				}
			case 0: /* EOF */
				teamd_ttdp_log_dbgx(ttdp_ppriv, "Early EOF in HELLO frame, idx %d", tlv_idx);
				return 1;
			case 1:
			case 2:
			case 3:
			default:
				offset += (tlv_len + 2);
				break;
		}
	}
	teamd_ttdp_log_dbgx(ttdp_ppriv, "No relevant TLVs in HELLO frame, idx %d", tlv_idx);
	return 1;
}

static void store_hello_frame(struct ttdp_hello_tlv* data) {
	memcpy(&(hello_data_storage[hello_data_storage_next_idx]), data, sizeof(struct ttdp_hello_tlv));
	hello_data_storage_next_idx = (hello_data_storage_next_idx + 1) % RINGBUF_SIZE;
}

static int ttdp_frame_is_peer_status_ok(struct ttdp_hello_tlv* hello_recv) {
	/* return 0 if the peer claims he can hear us */

	int idx = hello_recv->egressLine - 'A';
	/* 2 bits per line, with line A to the left: AABBCCDD */
	uint8_t peer_status = ((hello_recv->recvStatuses >> (6-(2*idx))) & 3);
	return (peer_status == 2) ? 0 : 1; /* status 2 means OK */
}

static void set_neigh_hears_us(struct teamd_context *ctx, struct lw_ttdp_port_priv* ttdp_ppriv, bool state) {
	struct ab *ab = (struct ab*)ctx->runner_priv;
	if (!ab)
		return;
	bool prev = ab->lines_heard[ttdp_ppriv->line];
	ttdp_ppriv->heard = state;
	ab->lines_heard[ttdp_ppriv->line] = state;
	if (prev != state) {
		if (ab->line_state_update_func) {
			ab->line_state_update_func(ctx, ctx->runner_priv);
			update_parent_port_status(ctx, ttdp_ppriv);
		}
	}
}

static int lw_ttdp_receive(struct teamd_context *ctx, int events, void *priv) {
	struct lw_ttdp_port_priv* ttdp_ppriv = (struct lw_ttdp_port_priv*)priv;
	static struct ttdp_hello_tlv hello_recv;
	//fprintf(stderr, "ttdp lw: lw_ttdp_receive\n");

	/* Receive and parse TTDP HELLO message here */
	static u_int8_t buf[TTDP_HELLO_FRAME_SIZE_MAX];
	struct sockaddr_ll ll_from;

	memset(&hello_recv, 0, sizeof(hello_recv));

	int err = teamd_recvfrom(ttdp_ppriv->start.psr.sock, &buf, TTDP_HELLO_FRAME_SIZE_MAX, 0,
			     (struct sockaddr *) &ll_from, sizeof(ll_from));
	if (err <= 0) {
		teamd_ttdp_log_dbgx(ttdp_ppriv, "Error %d from recvfrom", err);
		return err;
	}

	if (ttdp_ppriv->deaf == true)
		return 0;

	//fprintf(stderr, "Parsing TTDP HELLO frame, length %d\n", err);

	/* FIXME this should maybe be decoupled from _recv and not done immediately */
	/* see ab_state_active_port_set() in teamd_runner_activebackup.c */
	if (parse_ttdp_frame(buf, err, &hello_recv, ttdp_ppriv, ctx) == 0) {

		/* Stop the line status timer until we know what to do */
		teamd_loop_callback_timer_set(
			ctx,
			TTDP_PERIODIC_FORGET_PEER_CB_NAME,
			priv,
			&(ttdp_ppriv->forget_peer),
			&(ttdp_ppriv->forget_peer));
		teamd_loop_callback_disable(ctx, TTDP_PERIODIC_FORGET_PEER_CB_NAME, priv);

		if (ttdp_frame_is_peer_status_ok(&hello_recv) != 0) {
			/* Received a frame from a neighbor that doesn't hear us */
			/* Set our peer status to OK, but don't set link logical state to up */

			// teamd_ttdp_log_infox(ttdp_ppriv, "AGREE Got peer frame with bad RecvStatus "
			// 	"%c %d %.4X %d %d %d   %d",
			// 	hello_recv.egressLine,
			// 	hello_recv.egressLine,
			// 	hello_recv.recvStatuses,

			// 	(hello_recv.egressLine - 'A'),
			// 	(2*(hello_recv.egressLine - 'A')),
			// 	(6-(2*(hello_recv.egressLine - 'A'))),

			// 	((hello_recv.recvStatuses >> (6-(2*(hello_recv.egressLine - 'A')))) & 3)
			// 	);

			/* FIXME should have a separate timer here, to set recvstatus back
			 * down to ERROR in case we don't get frames for a while */

			set_neigh_hears_us(ctx, ttdp_ppriv, false);

			force_parent_port_status(ctx, ttdp_ppriv, 2);
			if (ttdp_ppriv->forget_peer_timer_running == false)
				teamd_ttdp_log_infox(ttdp_ppriv, "Neighbor heard - starting line status timer...");

			ttdp_ppriv->forget_peer_timer_running = true;
			teamd_loop_callback_enable(ctx, TTDP_PERIODIC_FORGET_PEER_CB_NAME, priv);

			if (ttdp_ppriv->strict_peer_recv_status) {
				/* If this option is set, we require the peer to also hear us
				 * before we let the line come up. Otherwise, continue as normal */
				return 0;
			}
		}

		/* valid frame received */

#ifdef TTDP_PHYSICAL_LINK_STATE_OVERRIDE
		/* reset link down delay, if any */
		if (ttdp_ppriv->local_phy_link_event_delayed) {
			teamd_loop_callback_disable(ctx, TTDP_PERIODIC_LINK_STATE_DELAY_CB_NAME, priv);
			teamd_ttdp_log_infox(ttdp_ppriv, "Resetting link state DOWN reporting delay due to HELLO frame");
			teamd_loop_callback_timer_set(ctx,
				TTDP_PERIODIC_LINK_STATE_DELAY_CB_NAME,
				priv,
				NULL,
				&(ttdp_ppriv->link_state_delay_down));
			teamd_loop_callback_enable(ctx, TTDP_PERIODIC_LINK_STATE_DELAY_CB_NAME, priv);
		}
#endif

		if (ttdp_ppriv->local_recovery_mode) {
			ttdp_ppriv->local_recovery_mode = 0;
			/* reset recovery mode timers */
			teamd_loop_callback_disable(ctx, TTDP_PERIODIC_FAST_TIMEOUT_CB_NAME, priv);
			teamd_loop_callback_disable(ctx, TTDP_PERIODIC_SLOW_TIMEOUT_CB_NAME, priv);

			teamd_loop_callback_timer_set(ctx,
				TTDP_PERIODIC_SLOW_TIMEOUT_CB_NAME,
				priv,
				&(ttdp_ppriv->slow_timeout),
				&(ttdp_ppriv->slow_timeout));
			teamd_loop_callback_enable(ctx, TTDP_PERIODIC_SLOW_TIMEOUT_CB_NAME, priv);

			/* Stop sending in fast mode && start sending in slow mode again */
			teamd_ttdp_log_infox(ttdp_ppriv, "Recovered - logical link state is now NO LONGER PENDING");
			ttdp_start_slow_send_timer(ctx, ttdp_ppriv);

		} else {

			teamd_loop_callback_disable(ctx, TTDP_PERIODIC_FAST_TIMEOUT_CB_NAME, priv);
			teamd_loop_callback_disable(ctx, TTDP_PERIODIC_SLOW_TIMEOUT_CB_NAME, priv);
			teamd_loop_callback_timer_set(ctx,
				TTDP_PERIODIC_SLOW_TIMEOUT_CB_NAME,
				priv,
				&(ttdp_ppriv->slow_timeout),
				&(ttdp_ppriv->slow_timeout));
			teamd_loop_callback_enable(ctx, TTDP_PERIODIC_SLOW_TIMEOUT_CB_NAME, priv);
		}

		store_hello_frame(&hello_recv);

		/* do necessary processing; store prev_neighbor; notify the runner of changes */
		update_neighbor(ttdp_ppriv, hello_recv.srcId.ether_addr_octet, hello_recv.cstUUid, hello_recv.etbTopoCnt);

		int notify = 0;
		if ((memcmp(ttdp_ppriv->neighbor_uuid, ttdp_ppriv->prev_neighbor_uuid,
			sizeof(ttdp_ppriv->neighbor_uuid)) != 0)
			|| (memcmp(ttdp_ppriv->neighbor_mac, ttdp_ppriv->prev_neighbor_mac,
			sizeof(ttdp_ppriv->neighbor_mac)) != 0)) {

			/* neighbor change detected, setup runner data & notify the runner */
			teamd_ttdp_log_infox(ttdp_ppriv, "New neighbor detected!");
			struct ab* p = (struct ab*)ctx->runner_priv;

			if (p && ttdp_ppriv->line <= TTDP_MAX_PORTS_PER_TEAM) {
				/* copy uuid */
				memcpy(p->neighbors[ttdp_ppriv->line].neighbor_uuid, ttdp_ppriv->neighbor_uuid,
					sizeof(p->neighbors[ttdp_ppriv->line].neighbor_uuid));
				/* copy mac */
				memcpy(p->neighbors[ttdp_ppriv->line].neighbor_mac, ttdp_ppriv->neighbor_mac,
					sizeof(p->neighbors[ttdp_ppriv->line].neighbor_mac));
				/* copy previous uuid */
				memcpy(p->prev_neighbors[ttdp_ppriv->line].neighbor_uuid, ttdp_ppriv->prev_neighbor_uuid,
					sizeof(p->prev_neighbors[ttdp_ppriv->line].neighbor_uuid));
				/* copy previous mac */
				memcpy(p->prev_neighbors[ttdp_ppriv->line].neighbor_mac, ttdp_ppriv->prev_neighbor_mac,
					sizeof(p->prev_neighbors[ttdp_ppriv->line].neighbor_mac));
				/* finally, update this... should not be needed every time */
				p->ifindex_by_line[ttdp_ppriv->line] = ttdp_ppriv->start.common.tdport->ifindex;
			} else {
				/* Should never happen, leaving it here for future 4-line support */
			}
			notify = 1;
		}

		if (ttdp_ppriv->neighbor_topocnt != ttdp_ppriv->prev_neighbor_topocnt) {
			teamd_ttdp_log_infox(ttdp_ppriv, "Neighbor has new topocnt! %08X -> %08X",
				ttdp_ppriv->prev_neighbor_topocnt, ttdp_ppriv->neighbor_topocnt);
			ttdp_ppriv->prev_neighbor_topocnt = ttdp_ppriv->neighbor_topocnt;
			struct ab *p = (struct ab*)ctx->runner_priv;
			if (p && ttdp_ppriv->line <= TTDP_MAX_PORTS_PER_TEAM) {
				p->neighbors[ttdp_ppriv->line].neighbor_topocount = ttdp_ppriv->neighbor_topocnt;
			} else {
				/* Should never happen, leaving it here for future 4-line support */
			}
			notify = 1;
		}

		/* we don't force a new neighbor election on inhibition changes, just set it for
		 * the runner to consume */
		if (hello_recv.inaugInhibition != ttdp_ppriv->neighbor_inhibit) {
			struct ab *p = (struct ab*)ctx->runner_priv;
			ttdp_ppriv->neighbor_inhibit = hello_recv.inaugInhibition;
			p->neighbors[ttdp_ppriv->line].neighbor_inhibition_state
				= hello_recv.inaugInhibition;
			if (p->remote_inhibit_update_func) {
				p->remote_inhibit_update_func(ctx, p);
			}
		}

		if (notify)
			teamd_event_port_changed(ctx, ttdp_ppriv->start.common.tdport);


		if (ttdp_ppriv->local_ttdp_link_up != true || ttdp_ppriv->heard != true) {
			ttdp_ppriv->local_ttdp_link_up = true;
			ttdp_ppriv->forget_peer_timer_running = false;
			set_neigh_hears_us(ctx, ttdp_ppriv, true);
			update_parent_port_status(ctx, ttdp_ppriv);
			update_overall_state(ctx, ttdp_ppriv);
			teamd_ttdp_log_infox(ttdp_ppriv, "Logical link state is now UP");
		}

		if (hello_recv.timeoutSpeed == 2) {
			teamd_ttdp_log_dbgx(ttdp_ppriv, "Recv HELLO in FAST MODE, replying");
			/* send a reply */
			lw_ttdp_send(ctx, events, priv);
		}

	} else {
		teamd_ttdp_log_dbgx(ttdp_ppriv, "Invalid frame, aborting");
		return 1;
	}

	return 0;
}

/* This is called if the logical link is down, but we've heard our neighbor some time
 * ago. We have however not heard from them since, so it's time to lower the peer recv
 * status back down to ERROR. */
static int lw_ttdp_forget_peer(struct teamd_context* ctx, int events,
	void* priv) {
	struct lw_ttdp_port_priv *ttdp_ppriv = (struct lw_ttdp_port_priv *)priv;
	struct ab *ab = ctx->runner_priv;

	if ((ttdp_ppriv->local_phy_link_up == true)
		&& (ttdp_ppriv->local_ttdp_link_up == false)
		&& (ttdp_ppriv->forget_peer_timer_running == true)
		) {
		teamd_ttdp_log_infox(ttdp_ppriv, "Strict Peer timer expired - resetting line status");
		ab->neighbor_lines[ttdp_ppriv->line] = '-';
		force_parent_port_status(ctx, ttdp_ppriv, 1);
	}
	teamd_loop_callback_disable(ctx, TTDP_PERIODIC_FORGET_PEER_CB_NAME, priv);
	ttdp_ppriv->forget_peer_timer_running = false;
	return 0;
}

/* This callback is called after a delay if we delayed reporting of physical port status */
static int lw_ttdp_link_status_delayed(struct teamd_context *ctx, int events,
				     void *priv) {
	struct lw_common_port_priv *common_ppriv = priv;
	struct lw_ttdp_port_priv *ttdp_ppriv = (struct lw_ttdp_port_priv *)priv;

	struct teamd_port *tdport;
	bool link_up;

	tdport = common_ppriv->tdport;
	link_up = team_is_port_link_up(tdport->team_port);

	ttdp_ppriv->local_phy_link_event_delayed = false;
	ttdp_ppriv->local_phy_link_up = link_up;

	if (!link_up) {
		update_neighbor_to_none(ttdp_ppriv);
	}
	teamd_ttdp_log_infox(ttdp_ppriv, "Reporting delayed link state %s", link_up ? "UP" : "DOWN");

	//teamd_event_port_changed(ctx, tdport);
	update_parent_port_status(ctx, ttdp_ppriv);
	return update_overall_state(ctx, priv);
}

/* FIXME check if the delayed thing is actually aborted properly */
static int lw_ttdp_event_watch_port_changed(struct teamd_context *ctx,
					       struct teamd_port *tdport,
					       void *priv) {
	struct lw_common_port_priv *common_ppriv = priv;
	struct lw_ttdp_port_priv *ttdp_ppriv = (struct lw_ttdp_port_priv *)priv;
	teamd_ttdp_log_dbgx(ttdp_ppriv, "ttdp lw: lw_ttdp_event_watch_port_changed");
	//struct timespec delay;

	/* Check if we got a spurious event #1 (wrong interface) - these are from teamlib
	 * directly, not sure if they actually ever happen */
	if (common_ppriv->tdport != tdport ||
		!team_is_port_changed(tdport->team_port)) {
		//fprintf(stderr, "spurious event #1\n");
		return 0;
	}

	bool link_up = team_is_port_link_up(tdport->team_port);

	/* Check if we got a spurious event #2 (no state change) - these are from teamlib
	 * directly, not sure if they actually ever happen */
	//if (!teamd_link_watch_link_up_differs(common_ppriv, link_up)) {
	//	fprintf(stderr, "spurious event #2\n");
	//	return 0;
	//}

	teamd_ttdp_log_infox(ttdp_ppriv, "Physical link state is now %s", link_up ? "UP" : "DOWN");

	/* Disable any running delay callback, we'll restart later if needed */
	teamd_loop_callback_disable(ctx, TTDP_PERIODIC_LINK_STATE_DELAY_CB_NAME, priv);

	if (link_up) {
		/* Link went down -> up */
		if (timespec_is_zero(&(ttdp_ppriv->link_state_delay_up))) {
			/* No delay, report immediately */
			teamd_ttdp_log_infox(ttdp_ppriv, "Setting link state to UP immediately");
			ttdp_ppriv->local_phy_link_up = link_up;
			//return teamd_link_watch_check_link_up(ctx, tdport, common_ppriv, link_up);
			return lw_ttdp_link_status_delayed(ctx, 0, priv);
		} else {
			teamd_ttdp_log_infox(ttdp_ppriv, "Starting link state UP reporting delay");
			ttdp_ppriv->local_phy_link_event_delayed = true;
			teamd_loop_callback_timer_set(ctx,
				TTDP_PERIODIC_LINK_STATE_DELAY_CB_NAME,
				priv,
				NULL,
				&(ttdp_ppriv->link_state_delay_up));
			teamd_loop_callback_enable(ctx, TTDP_PERIODIC_LINK_STATE_DELAY_CB_NAME, priv);
			return 0;
		}
	} else {
		/* Link went up -> down */
		if (timespec_is_zero(&(ttdp_ppriv->link_state_delay_down))) {
			/* No delay, report immediately */
			teamd_ttdp_log_infox(ttdp_ppriv, "Setting link state to DOWN immediately");
			ttdp_ppriv->local_phy_link_up = link_up;
			//return teamd_link_watch_check_link_up(ctx, tdport, common_ppriv, link_up);
			return lw_ttdp_link_status_delayed(ctx, 0, priv);
		} else {
			teamd_ttdp_log_infox(ttdp_ppriv, "Starting link state DOWN reporting delay");
			ttdp_ppriv->local_phy_link_event_delayed = true;
			teamd_loop_callback_timer_set(ctx,
				TTDP_PERIODIC_LINK_STATE_DELAY_CB_NAME,
				priv,
				NULL,
				&(ttdp_ppriv->link_state_delay_down));
			teamd_loop_callback_enable(ctx, TTDP_PERIODIC_LINK_STATE_DELAY_CB_NAME, priv);
			return 0;
		}
	}

	return 0;
}

static const struct teamd_event_watch_ops lw_ttdp_port_watch_ops = {
	.port_changed = lw_ttdp_event_watch_port_changed,
};


static int lw_ttdp_port_added(struct teamd_context *ctx,
			    struct teamd_port *tdport,
			    void *priv, void *creator_priv)
{
	//struct ab * runner = creator_priv;
	struct lw_ttdp_port_priv *ttdp_ppriv = (struct lw_ttdp_port_priv *)priv;
	teamd_ttdp_log_dbgx(ttdp_ppriv, "ttdp lw: lw_ttdp_port_added");

	int err;

	/* load options & set timespec fields of ttdp_ppriv */
	err = lw_ttdp_load_options(ctx, tdport, priv);
	if (err) {
		teamd_log_err("Failed to parse options, aborting");
		return err;
	}

	/* newly added ports should be disabled in the aggregate until known good */
	//team_set_port_enabled(ctx->th, tdport->ifindex, false);

	/* set up remaining local data */
	ttdp_ppriv->local_recovery_mode = 0;
	ttdp_ppriv->silent = false;
	ttdp_ppriv->lifesign = 0;
	ttdp_ppriv->local_phy_link_event_delayed = false;
	ttdp_ppriv->local_ttdp_link_up = false;
	ttdp_ppriv->neighbor_inhibit = TTDP_LOGIC_UNDEFINED;
	ms_to_timespec(&ttdp_ppriv->immediate, 1);
	if (ttdp_ppriv->immediate_timer_start_mode) {
		ttdp_ppriv->initial_fast_interval = &ttdp_ppriv->immediate;
		ttdp_ppriv->initial_slow_interval = &ttdp_ppriv->immediate;
	} else {
		ttdp_ppriv->initial_fast_interval = &ttdp_ppriv->fast_interval;
		ttdp_ppriv->initial_slow_interval = &ttdp_ppriv->slow_interval;
	}
	stringify_uuid(ttdp_ppriv->local_uuid, ttdp_ppriv->local_uuid_str);


	err = lw_ttdp_sock_open(ttdp_ppriv);
	if (err) {
		teamd_log_err("Failed to create socket.");
		return err;
	}
	err = teamd_loop_callback_fd_add(ctx, TTDP_SOCKET_CB_NAME, ttdp_ppriv,
					 lw_ttdp_receive,
					 ttdp_ppriv->start.psr.sock,
					 TEAMD_LOOP_FD_EVENT_READ);
	if (err) {
		teamd_log_err("Failed add socket callback.");
	}


	err = team_set_port_user_linkup_enabled(ctx->th, tdport->ifindex, false);
	if (err) {
		teamd_log_err("%s: Failed to enable user linkup.",
			      tdport->ifname);
	}


	err = teamd_event_watch_register(ctx, &lw_ttdp_port_watch_ops, priv);
	if (err) {
		teamd_log_err("Failed to register event watch.");
		//goto delay_callback_del;
	}

	/* FIXME add error handling from here on */

	teamd_loop_callback_timer_add_set(
		ctx,
		TTDP_PERIODIC_FAST_TIMEOUT_CB_NAME,
		ttdp_ppriv,
		lw_ttdp_fail_recovery_mode,
		&(ttdp_ppriv->fast_timeout),
		&(ttdp_ppriv->fast_timeout));

	teamd_loop_callback_timer_add_set(
		ctx,
		TTDP_PERIODIC_SLOW_TIMEOUT_CB_NAME,
		ttdp_ppriv,
		lw_ttdp_enter_recovery_mode,
		&(ttdp_ppriv->slow_timeout),
		&(ttdp_ppriv->slow_timeout));

	teamd_loop_callback_timer_add(ctx,
		TTDP_PERIODIC_FORGET_PEER_CB_NAME,
		ttdp_ppriv,
		lw_ttdp_forget_peer);


	//teamd_loop_callback_enable(ctx, TTDP_PERIODIC_FAST_TIMEOUT_CB_NAME, ttdp_ppriv);

	//teamd_loop_callback_enable(ctx, TTDP_PERIODIC_SLOW_TIMEOUT_CB_NAME, ttdp_ppriv);


	/* This one we only add - it gets set up when needed upon link status change */
	teamd_loop_callback_timer_add(ctx, TTDP_PERIODIC_LINK_STATE_DELAY_CB_NAME,
					    ttdp_ppriv, lw_ttdp_link_status_delayed);

	teamd_loop_callback_enable(ctx, TTDP_SOCKET_CB_NAME, ttdp_ppriv);

	if (ttdp_ppriv->initial_mode == 2) {
		//teamd_ttdp_log_infox("Starting in fast mode");
		teamd_ttdp_log_infox(ttdp_ppriv, "Starting in FAST transmission mode");
		//teamd_loop_callback_enable(ctx, TTDP_PERIODIC_FAST_SEND_CB_NAME, ttdp_ppriv);
		ttdp_start_fast_send_timer(ctx, ttdp_ppriv);
	} else {
		//teamd_ttdp_log_infox("Starting in slow mode");
		teamd_ttdp_log_infox(ttdp_ppriv, "Starting in SLOW transmission mode");
		//teamd_loop_callback_enable(ctx, TTDP_PERIODIC_SLOW_SEND_CB_NAME, ttdp_ppriv);
		ttdp_start_slow_send_timer(ctx, ttdp_ppriv);
	}

	/* For the -2-5 SNMP MIB, we have to transmit out fast/slow timeout values to the runner.
	 * However, the MIB only contains one of each of these values, while we could theoretically
	 * have two configured runners with two links each, and each of those could have a different
	 * configured value. We solve this dilemma in the simplest way possible, by having all links
	 * report up their value to the runners, at which point the runners send it to TCNd, and the
	 * latest report is shown via SNMP. */
	struct ab* ab = ctx->runner_priv;
	ab->latest_line_fast_timeout_ms = timespec_to_ms(&(ttdp_ppriv->fast_timeout));
	ab->latest_line_slow_timeout_ms = timespec_to_ms(&(ttdp_ppriv->slow_timeout));
	if (ab->line_timeout_value_update_func) {
		ab->line_timeout_value_update_func(ctx, ab);
	}

	ttdp_ppriv->local_phy_link_up = team_is_port_link_up(tdport->team_port);
	return err;
}

static void lw_ttdp_port_removed(struct teamd_context *ctx,
			    struct teamd_port *tdport,
			    void *priv, void *creator_priv) {
	struct lw_ttdp_port_priv* ttdp_ppriv = priv;
	teamd_ttdp_log_dbgx(ttdp_ppriv, "ttdp lw: lw_ttdp_port_removed");
	teamd_event_watch_unregister(ctx, &lw_ttdp_port_watch_ops, priv);
	lw_ttdp_sock_close(priv);
}


static int lw_ttdp_get_overall_state(struct teamd_context *ctx,
					 struct team_state_gsc *gsc,
					 void *priv) {
	struct lw_ttdp_port_priv* ttdp_ppriv = priv;

	gsc->data.bool_val = get_overall_state(ttdp_ppriv);

	return 0;
}
static int lw_ttdp_get_physical_state(struct teamd_context *ctx,
					 struct team_state_gsc *gsc,
					 void *priv) {
	struct lw_ttdp_port_priv* ttdp_ppriv = priv;

	static const char* state_names[3] = { "UP", "WAIT", "DOWN" };

	int result = 0;
	bool state = ttdp_ppriv->local_phy_link_up;
	if (ttdp_ppriv->local_phy_link_event_delayed)
		result = 1;
	else result = (state ? 0 : 2);

	gsc->data.str_val.ptr = state_names[result];
	return 0;
}
static int lw_ttdp_get_logical_state(struct teamd_context *ctx,
					 struct team_state_gsc *gsc,
					 void *priv) {
	struct lw_ttdp_port_priv* ttdp_ppriv = priv;

	gsc->data.bool_val = ttdp_ppriv->local_ttdp_link_up;
	return 0;
}
static int lw_ttdp_get_recovery_mode_state(struct teamd_context *ctx,
					 struct team_state_gsc *gsc,
					 void *priv) {
	struct lw_ttdp_port_priv* ttdp_ppriv = priv;

	gsc->data.bool_val = ttdp_ppriv->local_recovery_mode;
	return 0;
}

static int lw_ttdp_state_initial_mode_get(struct teamd_context *ctx,
					 struct team_state_gsc *gsc,
					 void *priv) {
	struct lw_ttdp_port_priv* ttdp_ppriv = priv;
	gsc->data.int_val = ttdp_ppriv->initial_mode;
	return 0;
}

static int lw_ttdp_get_fast_failed_recovery_mode(struct teamd_context *ctx,
					 struct team_state_gsc *gsc,
					 void *priv) {
	struct lw_ttdp_port_priv* ttdp_ppriv = priv;
	gsc->data.bool_val = ttdp_ppriv->fast_failed_recovery_mode;
	return 0;
}

static int lw_ttdp_set_fast_failed_recovery_mode(struct teamd_context *ctx,
					 struct team_state_gsc *gsc,
					 void *priv) {
	struct lw_ttdp_port_priv* ttdp_ppriv = priv;
	ttdp_ppriv->fast_failed_recovery_mode = gsc->data.bool_val;
	return 0;
}

static int lw_ttdp_state_delay_up_get(struct teamd_context *ctx,
					 struct team_state_gsc *gsc,
					 void *priv)
{
	struct lw_ttdp_port_priv* ttdp_ppriv = priv;
	struct timespec* ts;

	ts = &(ttdp_ppriv->link_state_delay_up);
	gsc->data.int_val = timespec_to_ms(ts);
	return 0;
}
static int lw_ttdp_state_delay_down_get(struct teamd_context *ctx,
					 struct team_state_gsc *gsc,
					 void *priv)
{
	struct lw_ttdp_port_priv* ttdp_ppriv = priv;
	struct timespec* ts;

	ts = &(ttdp_ppriv->link_state_delay_down);
	gsc->data.int_val = timespec_to_ms(ts);
	return 0;
}

static int lw_ttdp_immediate_timer_start_mode_get(struct teamd_context *ctx,
					 struct team_state_gsc *gsc,
					 void *priv) {
	struct lw_ttdp_port_priv* ttdp_ppriv = priv;
	gsc->data.bool_val = ttdp_ppriv->immediate_timer_start_mode;
	return 0;
}

static int lw_ttdp_slow_interval_get(struct teamd_context *ctx,
					 struct team_state_gsc *gsc,
					 void *priv) {
	struct lw_ttdp_port_priv* ttdp_ppriv = priv;
	struct timespec* ts;
	ts = &(ttdp_ppriv->slow_interval);
	gsc->data.int_val = timespec_to_ms(ts);
	return 0;
}
static int lw_ttdp_fast_interval_get(struct teamd_context *ctx,
					 struct team_state_gsc *gsc,
					 void *priv) {
	struct lw_ttdp_port_priv* ttdp_ppriv = priv;
	struct timespec* ts;
	ts = &(ttdp_ppriv->fast_interval);
	gsc->data.int_val = timespec_to_ms(ts);
	return 0;
}
static int lw_ttdp_slow_timeout_get(struct teamd_context *ctx,
					 struct team_state_gsc *gsc,
					 void *priv) {
	struct lw_ttdp_port_priv* ttdp_ppriv = priv;
	struct timespec* ts;
	ts = &(ttdp_ppriv->slow_timeout);
	gsc->data.int_val = timespec_to_ms(ts);
	return 0;
}
static int lw_ttdp_fast_timeout_get(struct teamd_context *ctx,
					 struct team_state_gsc *gsc,
					 void *priv) {
	struct lw_ttdp_port_priv* ttdp_ppriv = priv;
	struct timespec* ts;
	ts = &(ttdp_ppriv->fast_timeout);
	gsc->data.int_val = timespec_to_ms(ts);
	return 0;
}

static int lw_ttdp_forget_peer_timeout_get(struct teamd_context *ctx,
					 struct team_state_gsc *gsc,
					 void *priv) {
	struct lw_ttdp_port_priv* ttdp_ppriv = priv;
	struct timespec* ts;
	ts = &(ttdp_ppriv->forget_peer);
	gsc->data.int_val = timespec_to_ms(ts);
	return 0;
}

static int lw_ttdp_local_uuid_get(struct teamd_context *ctx,
					 struct team_state_gsc *gsc,
					 void *priv) {
	struct lw_ttdp_port_priv* ttdp_ppriv = priv;
	gsc->data.str_val.ptr = ttdp_ppriv->local_uuid_str;
	return 0;
}

static int lw_ttdp_local_topocnt_get(struct teamd_context *ctx,
					 struct team_state_gsc *gsc,
					 void *priv) {
	struct lw_ttdp_port_priv* ttdp_ppriv = priv;
	struct ab* ab = ctx->runner_priv;
	int err = snprintf(ttdp_ppriv->local_topocnt_str, sizeof(ttdp_ppriv->local_topocnt_str),
		"%.8X", htonl(ab->etb_topo_counter));
	if (err > 0 && err < sizeof(ttdp_ppriv->local_topocnt_str)) {
		gsc->data.str_val.ptr = ttdp_ppriv->local_topocnt_str;
		return 0;
	} else return err;
}

static int lw_ttdp_identity_hwaddr_get(struct teamd_context *ctx,
					 struct team_state_gsc *gsc,
					 void *priv) {
	struct lw_ttdp_port_priv* ttdp_ppriv = priv;
	gsc->data.str_val.ptr = ttdp_ppriv->identity_hwaddr_str;
	return 0;
}

static int lw_ttdp_failed_crcs_get(struct teamd_context *ctx,
					 struct team_state_gsc *gsc,
					 void *priv) {
	struct lw_ttdp_port_priv* ttdp_ppriv = priv;
	gsc->data.int_val = ttdp_ppriv->checksum_fail_counter;
	return 0;
}

static int lw_ttdp_vendor_info_get(struct teamd_context *ctx,
				   struct team_state_gsc *gsc,
				  void *priv) {
	struct lw_ttdp_port_priv* ttdp_ppriv = priv;
	gsc->data.str_val.ptr = ttdp_ppriv->vendor_info;
	return 0;
}

static int lw_ttdp_dump_frames_set(struct teamd_context *ctx,
					 struct team_state_gsc *gsc,
					 void *priv) {
	//struct lw_ttdp_port_priv* ttdp_ppriv = priv;
	if (gsc && gsc->data.int_val > 0) {
		dump_hello_frames();
	} else {
		hello_data_storage_next_idx++;
	}
	return 0;
}

static int lw_ttdp_clear_neighbor_set(struct teamd_context *ctx,
					 struct team_state_gsc *gsc,
					 void *priv) {
	struct lw_ttdp_port_priv* ttdp_ppriv = priv;
	if (gsc && gsc->data.int_val > 0) {
		update_neighbor_to_none(ttdp_ppriv);
	}
	return 0;
}


static int lw_ttdp_remote_uuid_get(struct teamd_context *ctx,
					 struct team_state_gsc *gsc,
					 void *priv) {
	struct lw_ttdp_port_priv* ttdp_ppriv = priv;
	stringify_uuid(ttdp_ppriv->neighbor_uuid, ttdp_ppriv->remote_uuid_str);
	gsc->data.str_val.ptr = ttdp_ppriv->remote_uuid_str;
	return 0;
}

static int lw_ttdp_remote_mac_get(struct teamd_context *ctx,
					 struct team_state_gsc *gsc,
					 void *priv) {
	struct lw_ttdp_port_priv* ttdp_ppriv = priv;
	int err = snprintf(ttdp_ppriv->remote_mac_str, sizeof(ttdp_ppriv->remote_mac_str),
		"%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
		ttdp_ppriv->neighbor_mac[0],
		ttdp_ppriv->neighbor_mac[1],
		ttdp_ppriv->neighbor_mac[2],
		ttdp_ppriv->neighbor_mac[3],
		ttdp_ppriv->neighbor_mac[4],
		ttdp_ppriv->neighbor_mac[5]
		);
	if (err > 0 && err < sizeof(ttdp_ppriv->remote_mac_str)) {
		gsc->data.str_val.ptr = ttdp_ppriv->remote_mac_str;
		return 0;
	} else return err;
}

static int lw_ttdp_remote_topocnt_get(struct teamd_context *ctx,
					 struct team_state_gsc *gsc,
					 void *priv) {
	struct lw_ttdp_port_priv* ttdp_ppriv = priv;
	int err = snprintf(ttdp_ppriv->remote_topocnt_str, sizeof(ttdp_ppriv->remote_topocnt_str),
		"%.8X", htonl(ttdp_ppriv->neighbor_topocnt));
	if (err > 0 && err < sizeof(ttdp_ppriv->remote_topocnt_str)) {
		gsc->data.str_val.ptr = ttdp_ppriv->remote_topocnt_str;
		return 0;
	} else return err;
}

static int lw_ttdp_remote_inhibit_get(struct teamd_context *ctx,
					 struct team_state_gsc *gsc,
					 void *priv) {
	struct lw_ttdp_port_priv* ttdp_ppriv = priv;
	gsc->data.int_val = ttdp_ppriv->neighbor_inhibit;
	return 0;
}

static int lw_ttdp_linedir_get(struct teamd_context *ctx,
					 struct team_state_gsc *gsc,
					 void *priv) {
	struct lw_ttdp_port_priv* ttdp_ppriv = priv;
	int err = snprintf(ttdp_ppriv->linedir_str, sizeof(ttdp_ppriv->linedir_str),
		"%c%c",
		ttdp_ppriv->line == 0 ? 'A' : 'B',
		ttdp_ppriv->direction == 1 ? '1' : '2'
		);
	if (err > 0 && err < sizeof(ttdp_ppriv->linedir_str)) {
		gsc->data.str_val.ptr = ttdp_ppriv->linedir_str;
		return 0;
	} else return err;
}

static int strict_peer_recv_status_get(struct teamd_context *ctx,
					 struct team_state_gsc *gsc,
					 void *priv) {
	struct lw_ttdp_port_priv* ttdp_ppriv = priv;
	gsc->data.bool_val = ttdp_ppriv->strict_peer_recv_status;
	return 0;
}

static int lw_ttdp_silent_get(struct teamd_context *ctx,
					 struct team_state_gsc *gsc,
					 void *priv) {
	struct lw_ttdp_port_priv* ttdp_ppriv = priv;
	gsc->data.int_val = (ttdp_ppriv->silent == true) ? 1 : 0;
	return 0;
}

static int lw_ttdp_silent_set(struct teamd_context *ctx,
					 struct team_state_gsc *gsc,
					 void *priv) {
	struct lw_ttdp_port_priv* ttdp_ppriv = priv;
	ttdp_ppriv->silent = (gsc->data.int_val == 1) ? true : false;
	return 0;
}

static int lw_ttdp_member_get(struct teamd_context *ctx,
					 struct team_state_gsc *gsc,
					 void *priv) {
	struct lw_ttdp_port_priv* ttdp_ppriv = priv;
	bool val = false;
	team_get_port_user_linkup(ctx->th, ttdp_ppriv->start.common.tdport->ifindex, &val);
	//teamd_port_enabled(ctx, ttdp_ppriv->start.common.tdport, &val);
	gsc->data.bool_val = val;
	return 0;
}

static int lw_ttdp_force_disabled_get(struct teamd_context *ctx,
					 struct team_state_gsc *gsc,
					 void *priv) {
	struct lw_ttdp_port_priv* ttdp_ppriv = priv;
	gsc->data.bool_val = ttdp_ppriv->deaf;
	return 0;
}

static int lw_ttdp_force_disabled_set(struct teamd_context *ctx,
					 struct team_state_gsc *gsc,
					 void *priv) {
	struct lw_ttdp_port_priv* ttdp_ppriv = priv;
	ttdp_ppriv->deaf = gsc->data.bool_val;
	if (gsc->data.bool_val == true) {
		//team_set_port_enabled(ctx->th, ttdp_ppriv->start.common.tdport->ifindex, false);
	} else {
		//team_set_port_enabled(ctx->th, ttdp_ppriv->start.common.tdport->ifindex, true);
		update_neighbor_to_none(ttdp_ppriv);
	}
	return 0;
}

static int lw_ttdp_noop(struct teamd_context __attribute__((unused)) *ctx,
				    struct team_state_gsc __attribute__((unused)) *gsc,
				    void __attribute__((unused)) *priv) {
	return 0;
}

static const struct teamd_state_val lw_ttdp_state_vals[] = {
	/* Runtime state */
	{
		.subpath = "overall_link_state",
		.type = TEAMD_STATE_ITEM_TYPE_BOOL,
		.getter = lw_ttdp_get_overall_state,
	},

	/* Return 0 for down, 1 for intermediate state (delayed transition), 2 for up */
	{
		.subpath = "physical_link_state",
		.type = TEAMD_STATE_ITEM_TYPE_STRING,
		.getter = lw_ttdp_get_physical_state,
	},

	{
		.subpath = "logical_link_state",
		.type = TEAMD_STATE_ITEM_TYPE_BOOL,
		.getter = lw_ttdp_get_logical_state,
	},

	{
		.subpath = "recovery_mode",
		.type = TEAMD_STATE_ITEM_TYPE_BOOL,
		.getter = lw_ttdp_get_recovery_mode_state,
	},

	/* Config variables */
	/* The sending mode that we should start in. 1 is slow, 2 is fast, anything else
	 * is slow */
	{
		.subpath = "initial_mode",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = lw_ttdp_state_initial_mode_get,
	},

	/* If enabled, we stay in FAST mode after failing recovery; otherwise, return to SLOW mode */
	{
		.subpath = "fast_failed_recovery_mode",
		.type = TEAMD_STATE_ITEM_TYPE_BOOL,
		.getter = lw_ttdp_get_fast_failed_recovery_mode,
		.setter = lw_ttdp_set_fast_failed_recovery_mode,
	},

	/* Ethernet physical link status delays */
	{
		.subpath = "link_state_delay_up",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = lw_ttdp_state_delay_up_get,
	},
	{
		.subpath = "link_state_delay_down",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = lw_ttdp_state_delay_down_get,
	},

	{
		.subpath = "immediate_timer_start_mode",
		.type = TEAMD_STATE_ITEM_TYPE_BOOL,
		.getter = lw_ttdp_immediate_timer_start_mode_get,
	},

	/* Slow mode sending interval in ms, aka SlowPeriod (recommended 100 ms) */
	{
		.subpath = "slow_interval",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = lw_ttdp_slow_interval_get,
	},

	/* Fast mode sending interval in ms, aka FastPeriod (rec. 15 ms) */
	{
		.subpath = "fast_interval",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = lw_ttdp_fast_interval_get,
	},

	/* Recovery mode enter timeout in ms, aka SlowTimeout (rec. 130 ms) */
	{
		.subpath = "slow_timeout",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = lw_ttdp_slow_timeout_get,
	},

	/* Recovery mode exit timeout in ms, aka FastTimeout (rec. 45 ms) */
	{
		.subpath = "fast_timeout",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = lw_ttdp_fast_timeout_get,
	},

	{
		.subpath = "forget_peer_timeout",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = lw_ttdp_forget_peer_timeout_get,
	},

	{
		.subpath = "local_uuid",
		.type = TEAMD_STATE_ITEM_TYPE_STRING,
		.getter = lw_ttdp_local_uuid_get,
	},

	{
		.subpath = "local_topocnt",
		.type = TEAMD_STATE_ITEM_TYPE_STRING,
		.getter = lw_ttdp_local_topocnt_get,
	},

	{
		.subpath = "identity_hwaddr",
		.type = TEAMD_STATE_ITEM_TYPE_STRING,
		.getter = lw_ttdp_identity_hwaddr_get,
	},

	{
		.subpath = "strict_peer_recv_status",
		.type = TEAMD_STATE_ITEM_TYPE_BOOL,
		.getter = strict_peer_recv_status_get,
	},

	{
		.subpath = "failed_crcs",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = lw_ttdp_failed_crcs_get,
	},

	{
		.subpath = "current_neighbor_uuid",
		.type = TEAMD_STATE_ITEM_TYPE_STRING,
		.getter = lw_ttdp_remote_uuid_get,
	},

	{
		.subpath = "current_neighbor_mac",
		.type = TEAMD_STATE_ITEM_TYPE_STRING,
		.getter = lw_ttdp_remote_mac_get,
	},

	{
		.subpath = "current_neighbor_topocnt",
		.type = TEAMD_STATE_ITEM_TYPE_STRING,
		.getter = lw_ttdp_remote_topocnt_get,
	},

	{
		.subpath = "current_neighbor_inhibit_antivalent",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = lw_ttdp_remote_inhibit_get,
	},

	{
		.subpath = "line_and_direction",
		.type = TEAMD_STATE_ITEM_TYPE_STRING,
		.getter = lw_ttdp_linedir_get,
	},

	{
		.subpath = "enabled_in_team",
		.type = TEAMD_STATE_ITEM_TYPE_BOOL,
		.getter = lw_ttdp_member_get,
	},

	/* triggers a dump of received HELLO frames */
	{
		.subpath = "poke_dump_frames",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = lw_ttdp_noop,
		.setter = lw_ttdp_dump_frames_set,
	},
	/* triggers a reset of memorized neighbor mac and uuid */
	{
		.subpath = "poke_clear_neighbor",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = lw_ttdp_noop,
		.setter = lw_ttdp_clear_neighbor_set,
	},
	/* if set to 1, operate as normal but never send any frames.
	 * if set to 0, or any other value, normal operation resumes */
	{
		.subpath = "poke_silent",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = lw_ttdp_silent_get,
		.setter = lw_ttdp_silent_set,
	},
	/* if set to 1, operate as normal but never send any frames.
	 * also forcibly remove myself from the aggregate.
	 * if set to 0, or any other value, normal operation resumes */
	{
		.subpath = "poke_deaf",
		.type = TEAMD_STATE_ITEM_TYPE_BOOL,
		.getter = lw_ttdp_force_disabled_get,
		.setter = lw_ttdp_force_disabled_set,
	},
	/* Value of the "vendor specific" field in transmitted HELLO frames. This
	 * can be set using the runner-scope configuration option
	 * "runner.vendor_info", but only takes effect on startup, and is then set
	 * in all of that runner's child linkwatchers. Up to 32 characters including
	 * a terminating zero byte are available. Read-only. */
	{
		.subpath = "vendor_info",
		.type = TEAMD_STATE_ITEM_TYPE_STRING,
		.getter = lw_ttdp_vendor_info_get,
	}
};

const struct teamd_link_watch teamd_link_watch_ttdp = {
	.name			= "ttdp",
	.state_vg		= {
		.vals		= lw_ttdp_state_vals,
		.vals_count	= ARRAY_SIZE(lw_ttdp_state_vals),
	},
	.port_priv = {
		.init		= lw_ttdp_port_added,
		.fini		= lw_ttdp_port_removed,
		.priv_size	= sizeof(struct lw_ttdp_port_priv),
	},
};
