/*
 *   teamd_lw_ttdp.h teamd TTDP structures & definitions
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
 */

#ifndef _TEAMD_LW_TTDP_H
#define _TEAMD_LW_TTDP_H

#include <linux/netdevice.h>
#include <linux/if_ether.h>

#include "teamd_workq.h"

/* ipc setting */
/* FIXME REMOVE */
#define TTDP_SILENT_NO_OUTPUT 1
#define TTDP_SILENT_NO_OUTPUT_INPUT 2
#define TTDP_NOT_SILENT 0

/* how many times to try sending the inital IPC data */
#define IPC_TRIES_MAX 5

#define TTDP_TOPOCNT_STR_BUF_SIZE 12

/* used for aggregate_status in struct ab */
#define TTDP_AGG_STATE_FLOATING_END 0
#define TTDP_AGG_STATE_FLOATING_MIDDLE 1
#define TTDP_AGG_STATE_FIXED_END 2
#define TTDP_AGG_STATE_FIXED_MIDDLE 3
#define TTDP_AGG_STATE_DEFAULT TTDP_AGG_STATE_FLOATING_END
#define TTDP_AGG_STATE_MAX TTDP_AGG_STATE_FIXED_MIDDLE

/* old behavior - don't disable disagreeing ports */
#define TTDP_NEIGH_AGREE_MODE_MULTI 0
/* new behavior - ensure that all ports that disagree with the currently elected
 * neighbor are disabled */
#define TTDP_NEIGH_AGREE_MODE_SINGLE 1
#define TTDP_NEIGH_AGREE_MODE_DEFAULT TTDP_NEIGH_AGREE_MODE_SINGLE

/* If this is defined, receipt of a HELLO frame will restart any active
 * physical link state down delay timer. */
#define TTDP_PHYSICAL_LINK_STATE_OVERRIDE

/* this has not been tested completely and is likely not needed */
//#define SET_USER_LINK
/* Define this to use port disabling/enabling in the aggregate. Without it,
 * we will not touch underlying aggregate functions. */
#define SET_PORT_ENABLED_DISABLED
/* Define this to force-enable all ports when going to FORWARDING mode. */
//#define FORCE_PORT_ENABLED_IN_FORWARDING
/* Define this to force-disable all ports when going to DISCARDING mode. */
#define FORCE_PORT_DISABLED_IN_DISCARDING

#define TTDP_NEIGH_PORT_DISAGREES 1
#define TTDP_NEIGH_PORT_AGREES 2

#define TTDP_INITIAL_MODE_SLOW 1
#define TTDP_INITIAL_MODE_FAST 2

#define TTDP_VENDOR_INFO_DEFAULT "UNSPECIFIED"

#include "teamd_link_watch.h"

/* FIXME: if this is changed, teamd_lw_ttdp needs to read its config better.
 * Look for teamd_config_int_get(ctx, &tmp, "@.direction" ...) */
#define TTDP_MAX_PORTS_PER_TEAM 2

#define TTDP_MAX_LINES 4

#define TTDP_LOGIC_FALSE 1
#define TTDP_LOGIC_TRUE 2
#define TTDP_LOGIC_UNDEFINED 3

#define TTDP_PORT_STATE_DISABLED 0
#define TTDP_PORT_STATE_ERROR 1
#define TTDP_PORT_STATE_FORWARDING 2
#define TTDP_PORT_STATE_DISCARDING 3

/* private data for a single ttdp port/linkwatcher */
struct lw_ttdp_port_priv {
	union {
		struct lw_common_port_priv common;
		struct lw_psr_port_priv psr;
	} start; /* must be first */

	/* USER OPTIONS */
	/* TTDP slow interval, default is TTDP_SLOW_INTERVAL_DEFAULT */
	struct timespec slow_interval;
	/* TTDP fast interval, default is TTDP_FAST_INTERVAL_DEFAULT */
	struct timespec fast_interval;

	/* Timeout before we go from slow to fast (recovery) mode, default is
	 * TTDP_SLOW_TIMEOUT_DEFAULT */
	struct timespec slow_timeout;
	/* Time after which, if in recovery mode, we consider logical link status as
	 * down. Default is TTDP_FAST_TIMEOUT_DEFAULT */
	struct timespec fast_timeout;

	/* set to 1 ms, and used as a value for "don't wait" below */
	struct timespec immediate;
	/* depending on the value of immediate_timer_start_mode below, these variables
	 * are either set to the respective _interval values, or to 'immediate'. The
	 * values are then used as the length of the first interval of the respective
	 * send timer - thus, if immediate_timer_start_mode is true, the first time we
	 * try to send the corresponding emssage we will do so immediately and not
	 * wait for the whole interval. */
	struct timespec* initial_slow_interval; /* either immediate or slow_interval */
	struct timespec* initial_fast_interval; /* either immediate or fast_interval */

	/* These delays control how long we wait after a change of the physical link
	 * state before reportng & accepting such a change. If the change is reversed
	 * withing the delay, we don't report it at all. */
	/* default is TTDP_LINK_STATE_DELAY_UP_DEFAULT */
	struct timespec link_state_delay_up;
	/* default is TTDP_LINK_STATE_DELAY_DOWN_DEFAULT */
	struct timespec link_state_delay_down;

	/* Transmission mode to start in initially - 1 for SLOW and 2 for FAST.
	 * Default is 1 (slow). */
	int initial_mode;
	/* Transmission mode to enter when we've given up recovery i.e. when no
	 * neighbor is talking to us. If set to TRUE, we remain in fast transmission
	 * mode; if set to FALSE, we jump back into slow mode. We consider logical
	 * link state as down in both cases regardless. Default is FALSE. */
	bool fast_failed_recovery_mode;

	/* This controls the start values of the initial interval timers above. Set
	 * in the configuration file and only used at startup. */
	bool immediate_timer_start_mode;

	/* If FALSE, we ignore the "peer_recv" flag in incoming telegrams. This lets
	 * us consider the port as up even though the neighbor says they cannot hear
	 * us. If TRUE, use the 61375 behavior, where we shall consider the logical
	 * port status as down, even if we can hear a neighbor, but that neighbor
	 * has these flags set to 0 - indicating that they cannot hear us. */
	bool strict_peer_recv_status;

	/* How long to wait for before permanently forgetting a neighbor. When this
	 * expires, we set the "neighbor lines" values in outbound telegrams to '-'
	 * for all of our lines. Default is TTDP_FORGET_PEER_TIMEOUT_DEFAULT */
	struct timespec forget_peer;
	/* Set to TRUE whenever the forget_peer timer mentioned above is running. */
	bool forget_peer_timer_running;

	/* ttdp direction of our parent aggregate, 1 or 2 */
	uint8_t direction;
	/* ttdp line of this link, 0 for 'A', or 1 for 'B' */
	uint8_t line;
	/* String version of the above. Set on configuration load. */
	char linedir_str[3];

	/* Local UUID of the consist that our parent is part of. */
	uint8_t local_uuid[16];
	/* String version of the above - set on configuration load. */
	char local_uuid_str[37];
	char vendor_info[32];

	/* Buffer to hold the string value of the current topocount. This is set by
	 * the getter function and almost always outdated, except for immediately
	 * when the state var is being read. */
	char local_topocnt_str[12];

	/* This points to either identity_hwaddr or the hwaddr of the team device.
	 * The latter case is useful mostly for testing as it will often result in
	 * broken topologies, since the two team devices on a node often have
	 * different MACS - and this in turn results in them being seen as two
	 * different nodes on the ETB. The value is set on configuration load. */
	char* identity_hwaddr_ptr;
	/* Buffer to hold the identity MAC address set at configuration time. */
	char identity_hwaddr[ETH_ALEN];
	/* String version of the above, read at configuration time */
	char identity_hwaddr_str[18];

	/* This holds the MAC address used for the mandatory LLDP TLV in the HELLO
	 * frame. Should not be used for anything of importance. */
	char chassis_hwaddr[ETH_ALEN];

	/* CURRENT INTERNAL STATE */
	/* current physical status */
	bool local_phy_link_up;
	/* are we delaying a physical transition? */
	bool local_phy_link_event_delayed;
	/* current logical (TTDP HELLO) status */
	bool local_ttdp_link_up;
	/* are we currently in recovery mode? */
	bool local_recovery_mode;

	/* increments every time we've read a frame with an incorrect checksum. Note
	 * that this is not the topocounter, but the frame checksum of the entire
	 * HELLO frame. */
	uint32_t checksum_fail_counter;

	/* Current neighbor node MAC... */
	uint8_t neighbor_mac[ETH_ALEN];
	/* ...UUID... */
	uint8_t neighbor_uuid[16];
	/* ...topocnt... */
	uint32_t neighbor_topocnt;
	/* ...and inhibition flag. This one is stored as-is using TTDP logic
	 * (1 is FALSE, etc). */
	uint8_t neighbor_inhibit;

	/* As above, but these are saved from the previous neighbor node. */
	uint8_t prev_neighbor_mac[ETH_ALEN];
	uint8_t prev_neighbor_uuid[16];
	uint32_t prev_neighbor_topocnt;

	/* String buffers to hold the string versions of some neighbor values. They
	 * are only updated when the corresponding state var is read, and will be
	 * outdated/incorrect at other times. */
	char remote_uuid_str[37];
	char remote_mac_str[18];
	char remote_topocnt_str[12];

	/* Internal timer bookkeeping, whether transmission and timeout timers are
	 * running. */
	bool local_fast_timer_started;
	bool local_slow_timer_started;
	bool local_fast_timeout_started;
	bool local_slow_timeout_started;

	/* Lifesign value sent in HELLO frames and incrememnted every time. */
	uint16_t lifesign;

	/* This gets set to TRUE if the neighbor reports that he can hear our frames
	 * on this line. */
	bool heard;

	/* TEST MODES */
	/* if true, operate as normal but do not send any frames */
	bool silent;
	/* if true, discard all incoming HELLO frames */
	bool deaf;
};

/* Structure that holds all data for a single neighbor. */
struct ttdp_neighbor {
	uint32_t neighbor_topocount;
	uint8_t neighbor_mac[ETH_ALEN];
	uint8_t neighbor_uuid[16];
	uint8_t neighbor_inhibition_state;
};

/* Structure for holding statistics hello frames and fast mode activation */
struct hello_stats {
	uint32_t sent_hello_frames;
	uint32_t recv_hello_frames;
	uint32_t local_fast_activated;
	uint32_t remote_fast_activated;
};

/* Private data for one runner/aggregate. Nevermind the name, this used to be
 * the activebackup runner at one point. */
struct ab {
	uint32_t active_ifindex;
	char active_orig_hwaddr[MAX_ADDR_LEN];
	const struct ab_hwaddr_policy *hwaddr_policy;
	int hwaddr_policy_first_set;
	struct teamd_workq link_watch_handler_workq;
	struct teamd_workq tcnd_notify_tcnd_workq;
	struct teamd_workq link_state_update_workq;
	struct teamd_workq remote_inhibition_workq;
	struct teamd_workq link_timeout_update_workq;

	/* maps an ifindex to a line number. Because reasons, this
	 * is updated by the lws every time and needs to be improved. */
	uint32_t ifindex_by_line[TTDP_MAX_PORTS_PER_TEAM];

	/* direction of this aggregate - should be the same as direction of all
	 * members lest weirdness ensue */
	uint8_t direction;

	/* This is one of the TTDP_SILENT_ defines above, or TTDP_NOT_SILENT. This
	 * controls how much we send/receive via IPC. Deprecated and to be removed.
	 * */
	int silent;

	/* Whether we've set up the identity MAC (the address used to identify this
	 * node) */
	bool identity_hwaddr_set;
	/* Identity MAC of this node. See the corresponding field in the port struct
	 * above. */
	char identity_hwaddr[ETH_ALEN];
	/* String version of the above, read at configuration time */
	char identity_hwaddr_str[18];

	/* Used for LLDP TLVs for all children - see above */
	char chassis_hwaddr[ETH_ALEN];
	/* String version of the above, read at configuration time */
	char chassis_hwaddr_str[18];

	/* Whether we've set the local UUID. If we haven't set this is either the
	 * runner or the individual LWs, refuse to start. */
	bool local_uuid_set;
	/* Consist UUID, used for all children lws. See above. */
	uint8_t local_uuid[16];
	/* String version of the above, read at configuration time */
	char local_uuid_str[37];

	/* Current neighbors, by line. These are to be set by ttdp lws on neighbor
	 * change. [0] is our neighbor on line A, [1] is line B. */
	struct ttdp_neighbor neighbors[TTDP_MAX_PORTS_PER_TEAM];
	/* keep track of which ports we need to forcibly exclude from the aggregate
	 * 0 = don't touch, 1 = exclude, 2 = include */
	uint8_t neighbor_agreement[TTDP_MAX_PORTS_PER_TEAM];

	/* One of the TTDP_NEIGH_AGREE_MODE_ defines. Determines how we act with
	 * regards to member ports that disagree with a neighbor election. */
	uint8_t neighbor_agreement_mode;

	/* Each member sets whether its neighbor can hear it on that line.
	 * [0] for line A, and so on. */
	bool lines_heard[TTDP_MAX_PORTS_PER_TEAM];

	/* Each member sets which neighbor line it's connected to. Contains the line
	 * name character 'A' etc. Same indexation as above. */
	uint8_t neighbor_lines[TTDP_MAX_PORTS_PER_TEAM];

	/* 2 bits used per port, also set by the watcher directly. Up to 4 in the standard,
	 * but only TTDP_MAX_PORTS_PER_TEAM supported currently.
	 * The lw sets this in update_parent_port_status() before
	 * updating its overall state, which in turn calls one of the
	 * port event watchers in the runner */
	uint8_t port_statuses[4];
	/* same as above but packed into one byte - used in outbound telegrams */
	uint8_t port_statuses_b;
	/* copy of the above, used for comparisions and IPC updates */
	uint8_t port_statuses_b_prev;
	/* same as port_statuses, but whether we're distributing/blocking etc - NYI */
	// uint8_t port_states[4];

	/* Fields sent to us by IPC, read by our linkwatchers and transmitted in HELLO frames */
	/* topo counter */
	uint32_t etb_topo_counter;
	/* text buffer for the hex string representation of the above - only set when needed,
	 * so not always reliable */
	uint8_t etb_topo_counter_str[TTDP_TOPOCNT_STR_BUF_SIZE];

	/* Inhibition flags */
	/* Inhibition set on our node,; we get this via IPC */
	uint8_t inhibition_flag_local;
	/* Inhibition set on any node in our train; we get this via IPC (calculated
	 * higher up in the 61375 stack) */
	uint8_t inhibition_flag_any;
	/* As heard from our neighbor in their HELLO frames */
	uint8_t inhibition_flag_neighbor;
	/* In certain cases, when we are on a consist boundary, we set this and notify via IPC */
	uint8_t inhibition_flag_remote_consist;

	/* NYI */
	struct ttdp_neighbor prev_neighbors[TTDP_MAX_PORTS_PER_TEAM];

	/* This is the neighbor we've decided upon and will report up the stack */
	struct ttdp_neighbor elected_neighbor;
	/* This is elected_neighbor as of before the latest election */
	struct ttdp_neighbor prev_elected_neighbor;
	/* Set to 1 if our elected_neighbor above is "all zeroes" */
	int neighbor_is_none;

	/* Elected neighbor at the time of the latest positive edge of our parent
	 * node becoming inhibited (either by local request or due to train
	 * inhibition). This is used for end node management and recovery cases. */
	struct ttdp_neighbor fixed_elected_neighbor;
	/* Our local topocount at the inhibition time as described above. */
	uint32_t fixed_etb_topo_counter;

	/* String buffers to hold elected_neighbor values. These are populated by
	 * the corresponding state val getter functions, and will be outdated or
	 * incorrect at other times. */
	char elected_neighbor_uuid_str[37];
	char elected_neighbor_mac_str[18];
	char elected_neighbor_topocnt_str[12];
	/* Same as above, but for fixed_elected_neighbor. */
	char fixed_elected_neighbor_uuid_str[37];
	char fixed_elected_neighbor_mac_str[18];
	char fixed_elected_neighbor_topocnt_str[12];
	char neighbor_agreement_str[4];

	/* Vendor specific information string */
	char vendor_info[32];

	/* buffer used for the port_statuses statevar, up to 9 chars per port. Also
	 * set by the statevar getter. */
	char port_statuses_str[(9*4)+1];

	/* These values are used e.g. for SNMP. Since the MIB only wants one instance
	 * of each of these values, while they are individually configurable in each
	 * link watcher, we will just go with the latest. Each child linkwatcher sets
	 * these two variables to their configured values, and then calls
	 * line_timeout_value_update_func, at which point we send the IPC message.
	 * Higher up in the stack, the latest such message received is used to
	 * reply to SNMP queries for the values in question. */
	uint32_t latest_line_fast_timeout_ms;
	uint32_t latest_line_slow_timeout_ms;
	void*(*line_timeout_value_update_func)(void*,void*);

	/* The values in this struct are exposed as state variables, per line, and
	 * holds counters for how many HELLO frames have been sent/received and
	 * how many times fast mode has been activated. */
	struct hello_stats lines_hello_stats[TTDP_MAX_LINES];

	/* Child lws can call this function to notify us that a line state has changed,
	 * in cases that it does not happen automatically due to a port changing
	 * up/down state. */
	void*(*line_state_update_func)(void*,void*);
	/* Same as above, but called when the child has a neighbor inhibit update */
	void*(*remote_inhibit_update_func)(void*,void*);

	/* Current value of the remote-inhibition flag. This is sent via IPC
	 * and uses TTDP logic, UNDEFINED if n/a. */
	uint8_t remote_inhibition_actual;

	/* Current state of the aggregate state machine, one of the TTDP_AGG_STATE_*
	 * defines above */
	uint8_t aggregate_status;

	/* Current "aggregate port state" in the 61375 sense. All ports share this.
	 * Can be "DISCARDING" or "FORWARDING"; in the former case, ports will not be
	 * activated in the aggregate. Used by inhibited end nodes. */
	bool is_discarding;

	/* EXTERNALLY-SET VALUES */
	/* These values are set by other, external parts of the 61375 stack. This
	 * used to be done by our IPC, but is now done by the regular statevar
	 * functionality. */
	/* Set to TRUE whenever we are currently receiving valid TTDP TOPOLOGY frames
	 * from one or more nodes in this direction. These frames are received and
	 * parsed higher up in the stack, but we need to know whether we have
	 * neighbors in our direction. */
	bool receiving_topology_frames;
	/* Set to TRUE when the higher parts of the 61375-2-5 stack consider us
	 * inaugurated. This only refers to -2-5 inauguration - we don't care about
	 * -2-3 or any of the more advanced funtions here. This is used for our
	 * state machine with regards to end node management etc. */
	bool inaugurated;

	/* SHORTENING/LENGTHENING DETECTION */
	/* We set this to TRUE if we detect train shortening on the aggregate level.
	 * This can only be detected on the (post-shortening) end nodes.
	 * Specifically, if we previously
	 * - had a neighbor _from a different consist_,
	 * - find ourselves inhibited, and
	 * - no longer detect a neighbor, then we set this to TRUE. */
	bool shortening_detected;
	/* Conversely, we set this to TRUE when we detect lengthening. This can also
	 * only be detected on the end nodes while we're on the aggregate level
	 * (however, higher up in the 61375-2-5 stack we can detect this on every
	 * node). We detect a few different kinds of lengthening, and intend to be
	 * compatible with -2-5 in this regard. */
	bool lengthening_detected;

	/* DIAGNOSTICS */
	/* These are certain conditions that we can detect on the aggregate layer
	 * and warn about. Currently these warnings are  done by writing to a
	 * statefile, one per diagnostic condition. */
	/* Our ports are not mapped to out neighbor in order, i.e. 'A' to 'A', 'B'
	 * to 'B', and so on. This is indicative of a mistake in cabling. */
	bool crossed_lines_detected;
	/* Our in-consist neighbor in this direction has a different orientation
	 * than we do. In other words, our direction X is connected to the same
	 * direction X of our in-consist neighbor. This is indicative of a mistake
	 * in cabling, as the consist orientation becomes inconsistent. */
	bool mixed_consist_orientation_detected;
};

#endif
