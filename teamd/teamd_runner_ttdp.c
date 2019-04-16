/*
 *   teamd_lw_ttdp.c teamd TTDP runner
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

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/netdevice.h>
#include <limits.h>
#include "private/misc.h"
#include <team.h>

#include "teamd.h"
#include "teamd_config.h"
#include "teamd_state.h"
#include "teamd_workq.h"
#include "teamd_lw_ttdp.h"
#include "teamd_runner_ttdp_ipc.h"

/* This code is based on the the activebackup runner, with IEC61375-specific
   additions and changes. The following major changes have been made:
 - Sticky is now the default for all ports
 - Includes basic peer detection logic using IEC61375-2-5 TTDP HELLO
 - Does aggregate control, link supervision & end node management according to
   the above
 - Communicates neighbor detection & status to an IPC socket.
*/

/* Define to set user link up/down when ports don't agree with the elected neighbor */
// #define SET_USER_LINK
/* Define to set user link up/down on all ports when in FORWARDING/DISCARDING */
// #define SET_USER_LINK_TEAM_IFACE
/* Define to set link up/down on the agg iface when in FORWARDING/DISCARDING */
#define SET_LINK_TEAM_IFACE

#define TEAMNAME_OR_EMPTY(P) ((P)\
	? P : "ttdp-runner")

#ifdef DEBUG
#define teamd_ttdp_log_infox(P, format, args...) daemon_log(LOG_DEBUG, "%s: " format, TEAMNAME_OR_EMPTY(P), ## args)
#define teamd_ttdp_log_dbgx(P, format, args...) daemon_log(LOG_DEBUG, "%s: " format, TEAMNAME_OR_EMPTY(P), ## args)
#else
#define teamd_ttdp_log_infox(P, format, args...) do {} while (0)
#define teamd_ttdp_log_dbgx(P, format, args...) do {} while (0)
#endif
#define teamd_ttdp_log_info(format, args...) daemon_log(LOG_INFO, format, ## args)
#define teamd_ttdp_log_dbg(format, args...) daemon_log(LOG_DEBUG, format, ## args)
#define teamd_ttdp_log_warnx(P, format, args...) daemon_log(LOG_WARNING, "%s: " format, TEAMNAME_OR_EMPTY(P), ## args)


/* synchronize with teamd_lw_ttdp.h */
static const char* agg_state_strings[TTDP_AGG_STATE_MAX+1] = {
	"Floating end",
	"Floating intermediate",
	"Fixed end",
	"Fixed intermediate"
};
#define AGG_STATE_STRING(x) (((x >= 0) && (x <= TTDP_AGG_STATE_MAX)) ? agg_state_strings[x] : "NONE")

static const char* ttdp_runner_oneshot_initial_agg_state_name =
	"ttdp_runner_oneshot_initial_agg_state";
static struct timespec ttdp_runner_oneshot_timer = {
	.tv_sec = 5,
	.tv_nsec = 0
};

static const char* ttdp_runner_periodic_neighbor_macs_name = 
	"ttdp_runner_periodic_neighbor_macs";
static struct timespec ttdp_runner_periodic_neighbor_macs_timer = {
	.tv_sec = 0,
	.tv_nsec = 1000000000 /* 1 s */
};

static const char* port_state_strings[] = {"ERROR", "FALSE", " TRUE", "UNDEF"};
static int ab_link_watch_handler(struct teamd_context *ctx, struct ab *ab);
static int ab_link_watch_handler_internal(struct teamd_context *ctx, struct ab *ab,
	bool allow_update_aggregate_state);
void* remote_inhibition_update(void* c, void* a);

struct ab;
/* policy that determines what to do with MAC addresses of team & ports */
/* Uses the same policies as activebackup, with the addition of "first",
   which sets the team MAC to the one of the first added port, and then does nothing,
   and "none", which sets the team device to the "hwaddr" specified in the config,
   and then does nothing. */
struct ab_hwaddr_policy {
	const char *name;
	/* called when the hwaddr of the team device is changed */
	int (*hwaddr_changed)(struct teamd_context *ctx,
			      struct ab *data);
	/* called when a new port is added */
	int (*port_added)(struct teamd_context *ctx, struct ab *data,
			  struct teamd_port *tdport);
	/* called when a port becomes active */
	int (*active_set)(struct teamd_context *ctx, struct ab *data,
			  struct teamd_port *tdport);
	/* called when a port is no longer active */
	int (*active_clear)(struct teamd_context *ctx, struct ab *data,
			    struct teamd_port *tdport);
};

struct ab_port {
	struct teamd_port *tdport;
	struct {
		bool sticky;
#define		AB_DFLT_PORT_STICKY true
	} cfg;
};

static int is_uuid_none(const uint8_t* uuid) {
	static const uint8_t zero[16] = {0};
	return (memcmp(zero, uuid, sizeof(zero)) == 0);
}

static int is_mac_none(const uint8_t* mac) {
	static const uint8_t zero[ETH_ALEN] = {0};
	return (memcmp(zero, mac, sizeof(zero)) == 0);
}

static int is_neighbor_none(struct ttdp_neighbor* neigh) {
	return (is_uuid_none(neigh->neighbor_uuid) && is_mac_none(neigh->neighbor_mac));
}

static void all_ports_forwarding(struct teamd_context *ctx, struct ab* ab) {
teamd_ttdp_log_infox(ctx->team_devname, "Move to FORWARDING");
	struct team_port* port;
	ab->is_discarding = false;
	team_for_each_port(port, ctx->th) {
		uint32_t ifindex = team_get_port_ifindex(port);
		if (ab->neighbor_agreement_mode == TTDP_NEIGH_AGREE_MODE_SINGLE) {
			/* don't set ports with a known zero neighbor as enabled... */
			// for (int i = 0; i < TTDP_MAX_PORTS_PER_TEAM; ++i) {
			// 	if ((ab->ifindex_by_line[i] == ifindex) && !is_neighbor_none(&ab->neighbors[i])) {
		#if defined FORCE_PORT_ENABLED_IN_FORWARDING && defined SET_PORT_ENABLED_DISABLED
			team_set_port_enabled(ctx->th, ifindex, true);
		#endif
			// 	}
			// }
		} else if (ab->neighbor_agreement_mode == TTDP_NEIGH_AGREE_MODE_MULTI) {
		#ifdef SET_PORT_ENABLED_DISABLED
			team_set_port_enabled(ctx->th, ifindex, true);
		#endif
		}
		//team_set_port_user_linkup(ctx->th, ifindex, true);
		//teamd_ttdp_log_dbgx(ctx->team_devname, "set %d FORWARDING: %d", ifindex, err);
	}
		#ifdef SET_USER_LINK_TEAM_IFACE
			team_set_port_user_linkup(ctx->th, ctx->ifindex, true);
			// fprintf(stderr, "FORWARDING set user_link %d\n", ctx->ifindex);
		#endif
		#ifdef SET_LINK_TEAM_IFACE
			team_link_set(ctx->th, ctx->ifindex, true);
			// fprintf(stderr, "FORWARDING set link %d\n", ctx->ifindex);
		#endif

	ab_link_watch_handler_internal(ctx, ab, false);
}

static void all_ports_discarding(struct teamd_context *ctx, struct ab* ab) {
	teamd_ttdp_log_infox(ctx->team_devname, "Move to DISCARDING");
	struct team_port* port;
	ab->is_discarding = true;
	team_for_each_port(port, ctx->th) {
		uint32_t ifindex = team_get_port_ifindex(port);
	#if defined FORCE_PORT_DISABLED_IN_DISCARDING && defined SET_PORT_ENABLED_DISABLED
		team_set_port_enabled(ctx->th, ifindex, false);
	#endif
		//team_set_port_user_linkup(ctx->th, ifindex, false);
		//teamd_ttdp_log_dbgx(ctx->team_devname, "set %d BLOCKING: %d", ifindex, err);
	}
	#ifdef SET_USER_LINK_TEAM_IFACE
		team_set_port_user_linkup(ctx->th, ctx->ifindex, false);
		// fprintf(stderr, "DISCARDING set %d\n", ctx->ifindex);
	#endif
	#ifdef SET_LINK_TEAM_IFACE
		team_link_set(ctx->th, ctx->ifindex, false);
		// fprintf(stderr, "DISCARDING set link %d\n", ctx->ifindex);
	#endif
	//ab_link_watch_handler(ctx, ab);
}

static void set_shortening(struct teamd_context *ctx,
	struct ab* ab, bool shortening) {
	ab->shortening_detected = shortening;
	send_tcnd_shorten_lengthen_message(ctx, ab);
}

static void set_lengthening(struct teamd_context *ctx,
	struct ab* ab, bool lengthening) {
	ab->lengthening_detected = lengthening;
	send_tcnd_shorten_lengthen_message(ctx, ab);
}

static void clear_shorten_lengthen(struct teamd_context *ctx,
	struct ab* ab) {
	ab->shortening_detected = false;
	ab->lengthening_detected = false;
	send_tcnd_shorten_lengthen_message(ctx, ab);
}

static int detect_trivial_shortening(struct teamd_context *ctx,
	struct ab* ab) {
	/* trivial shortening case - used to have a neighbor from a different consist. */
	if (!is_neighbor_none(&ab->fixed_elected_neighbor)) {
		if ((memcmp(&ab->local_uuid, &ab->fixed_elected_neighbor.neighbor_uuid,
			sizeof(ab->local_uuid)) != 0)) {
			teamd_ttdp_log_infox(ctx->team_devname, "Trivial shortening detected.");
			return 1;
		}
	}
	return 0;
}

static int detect_trivial_lengthening(struct teamd_context *ctx,
	struct ab* ab) {
	/* trivial lengthening case - we were the last node of the fixed topology, and
	 * a node has come up that is across the consist boundary. */
	if (is_neighbor_none(&ab->fixed_elected_neighbor)) {
		if (!is_uuid_none(ab->elected_neighbor.neighbor_uuid)) {
			teamd_ttdp_log_infox(ctx->team_devname, "Trivial lengthening detected.");
			return 1;
		}
	}
	return 0;
}

static int detect_reappearing_lengthening(struct teamd_context *ctx,
	struct ab* ab) {
	/* reappearing neighbor consist case - same foreign consist is our neighbor */
	if (!is_uuid_none(ab->fixed_elected_neighbor.neighbor_uuid)) {
		if (memcmp(&ab->fixed_elected_neighbor.neighbor_uuid, &ab->local_uuid, 16) != 0) {
			if (memcmp(&ab->fixed_elected_neighbor.neighbor_uuid,
				&ab->elected_neighbor.neighbor_uuid, 16) == 0) {
				teamd_ttdp_log_infox(ctx->team_devname, "\'Reappearing consist\'' lengthening detected.");
				return 1;
			}
		}
	}
	return 0;
}

static int detect_neigh_node_recovery(struct teamd_context *ctx,
	struct ab* ab) {
	/* If a neighbor node with the same topocount as we have has come up
	 * next to us, we can move to FIXED MIDDLE. Do this only if the neighbor
	 * is not inhibited itself.
	 *
	 * Optionally, we could also do this regardless of anything if the node is
	 * the same one that we had previously, but for now we don't do this since
	 * there is no good way to guarantee that we only get that node, and not any
	 * nodes that might have appeared behind it. */

	/* only accept if no port has a neighbor who is not inhibited */
	int port_has_non_inhibited_neighbor = 0;
	for (int i = 0; i < TTDP_MAX_PORTS_PER_TEAM; ++i) {
		if (!is_neighbor_none(&ab->neighbors[i])) {
			port_has_non_inhibited_neighbor |= (ab->neighbors[i].neighbor_inhibition_state != 2);
		}
	}

	if ((!is_neighbor_none(&ab->elected_neighbor))
		/* the condition below is not checked by WeOS4!  */
		&& (ab->elected_neighbor.neighbor_topocount == ab->fixed_etb_topo_counter)
		&& (!port_has_non_inhibited_neighbor)
		) {
		if (memcmp(&ab->local_uuid, &ab->elected_neighbor.neighbor_uuid,
			sizeof(ab->local_uuid)) == 0) {
			teamd_ttdp_log_infox(ctx->team_devname, "Neighbor node recovery detected - same consist "
				"with agreeing topocount.");
		} else {
			teamd_ttdp_log_infox(ctx->team_devname, "Neighbor node recovery detected - remote consist "
				"with agreeing topocount.");
		}
		return 1;
	}
	// /* otherwise, if we lost and then recovered the same node, we may also
	//  * accept it. */
	// if (memcmp(&ab->fixed_elected_neighbor, &ab->elected_neighbor,
	// 	sizeof(ab->fixed_elected_neighbor)) == 0)
	// 	return 1;
	return 0;
}

static void memorize_neighbor(struct teamd_context *ctx, struct ab* ab) {
	memcpy(&(ab->fixed_elected_neighbor), &(ab->elected_neighbor),
		sizeof(ab->fixed_elected_neighbor));
	ab->fixed_etb_topo_counter = (ab->etb_topo_counter);
	teamd_ttdp_log_infox(ctx->team_devname, "Memorized neighbor with topocount %08X, own %08X",
		ab->fixed_etb_topo_counter, ab->etb_topo_counter);
}

static void forget_neighbor(struct teamd_context *ctx, struct ab* ab) {
	memset(&ab->fixed_elected_neighbor, 0, sizeof(ab->fixed_elected_neighbor));
	clear_shorten_lengthen(ctx, ab);
}
static int ab_clear_active_port(struct teamd_context *ctx, struct ab *ab,
				struct teamd_port *tdport);
static void move_to_aggregate_state(struct teamd_context *ctx,
	struct ab* ab, uint8_t next, bool change) {
	//uint8_t prev = ab->aggregate_status;
	/* when going from floating to fixed, do not touch the links, to avoid weird behavior */
	switch (next) {
		case TTDP_AGG_STATE_FLOATING_END:
			all_ports_forwarding(ctx, ab);
			break;
		case TTDP_AGG_STATE_FLOATING_MIDDLE:
			all_ports_forwarding(ctx, ab);
			break;
		case TTDP_AGG_STATE_FIXED_MIDDLE:
			// if (prev == TTDP_AGG_STATE_FLOATING_END
			// 	|| prev == TTDP_AGG_STATE_FLOATING_MIDDLE) {
			// 	do_refresh_links = 1;
			// }
			//ab_clear_active_port(ctx, ab, NULL);
			all_ports_forwarding(ctx, ab);
			break;
		case TTDP_AGG_STATE_FIXED_END:
			// if (prev == TTDP_AGG_STATE_FLOATING_END
			// 	|| prev == TTDP_AGG_STATE_FLOATING_MIDDLE) {
			// 	do_refresh_links = 1;
			// }
			all_ports_discarding(ctx, ab);
			break;
		default:
			break;
	}
	if (change) {
		ab->aggregate_status = next;
		ab_link_watch_handler(ctx, ab);
	}
	send_tcnd_role_message(ctx, ab);
}

uint8_t update_aggregate_state(struct teamd_context *ctx,
	struct ab* ab) {
	uint8_t current = ab->aggregate_status;
	uint8_t next = current;

	uint8_t inaugurated = ab->inaugurated;
	uint8_t inhibit_any = (ab->inhibition_flag_local | ab->inhibition_flag_any);
	uint8_t inhibit = ((inhibit_any & TTDP_LOGIC_TRUE) != 0);
	uint8_t mid = (ab->receiving_topology_frames) || !(is_neighbor_none(&ab->elected_neighbor));
	uint8_t end = !(mid);

	teamd_ttdp_log_infox(ctx->team_devname, "update state curr %d inaug %d inhibit %d "
		"end %d neighbor_zero(fixed) %d neighbor_zero(elect) %d",
		current, inaugurated, inhibit, end, is_neighbor_none(&ab->fixed_elected_neighbor),
		is_neighbor_none(&ab->elected_neighbor));

	if (inhibit && !inaugurated) {
		teamd_ttdp_log_warnx(ctx->team_devname, "state change while inhibited but not inaugurated; ignoring");
		return current;
	}

	switch (current) {
		case TTDP_AGG_STATE_FLOATING_END:
			if (inhibit && inaugurated) {
				memorize_neighbor(ctx, ab);
				next = TTDP_AGG_STATE_FIXED_END;
				break;
			} else if (!end) {
				next = TTDP_AGG_STATE_FLOATING_MIDDLE;
				forget_neighbor(ctx, ab);
				break;
			}
			break;
		case TTDP_AGG_STATE_FLOATING_MIDDLE:
			if (inhibit && inaugurated) {
				memorize_neighbor(ctx, ab);
				next = TTDP_AGG_STATE_FIXED_MIDDLE;
				break;
			} else if (end) {
				next = TTDP_AGG_STATE_FLOATING_END;
				forget_neighbor(ctx, ab);
			}
			break;
		case TTDP_AGG_STATE_FIXED_END:
			if (!inhibit) {
				/* if a node was discovered while we were gone, we need to become a
				 * middle node */
				if (!is_neighbor_none(&ab->elected_neighbor)) {
					teamd_ttdp_log_infox(ctx->team_devname,
						"Inhibit lifted, not end node anymore");
					next = TTDP_AGG_STATE_FLOATING_MIDDLE;
				} else {
					teamd_ttdp_log_infox(ctx->team_devname,
						"Inhibit lifted, still end node");
					next = TTDP_AGG_STATE_FLOATING_END;
				}
				forget_neighbor(ctx, ab);
				clear_shorten_lengthen(ctx, ab);
			} else if (detect_neigh_node_recovery(ctx, ab)) {
				/* node recovery - if another node in our own consist has come up,
				 * we are happy to move to FIXED MIDDLE */
				next = TTDP_AGG_STATE_FIXED_MIDDLE;
				clear_shorten_lengthen(ctx, ab);
				teamd_ttdp_log_infox(ctx->team_devname, "Neighbor node late/recovery detected!");
			} else if (detect_trivial_lengthening(ctx, ab)) {
				teamd_ttdp_log_infox(ctx->team_devname, "Lengthening detected due to new foreign node");
				set_lengthening(ctx, ab, true);
				next = TTDP_AGG_STATE_FIXED_END;
			} else if (!end && detect_reappearing_lengthening(ctx, ab)) {
				/* this is an odd one - we're an end aggregate but have detected a consist
				 * which does not lead to trivial lengthening. This is likely the same
				 * consist whose disappearance led us to becoming the end node. In this case
				 * we're expected to set shorten & lengthen, so set lengthen here. */
				set_lengthening(ctx, ab, true);
			} else if ((ab->lengthening_detected == true)
				&& is_neighbor_none(&ab->fixed_elected_neighbor)) {
				/* We had set lengthening before, but now have no neighbor. The consist that caused
				 * us to set lengthening in the first place must have disappeared again, so clear it. */
				set_lengthening(ctx, ab, false);
			}
			break;
		case TTDP_AGG_STATE_FIXED_MIDDLE:
			if (!inhibit) {
				next = TTDP_AGG_STATE_FLOATING_MIDDLE;
				forget_neighbor(ctx, ab);
				break;
			} else if (end) {
				next = TTDP_AGG_STATE_FIXED_END;
				/* We used to be a middle node, but are now at the end of the fixed topology.
			 	 * set shortening only if a complete consist has vanished, i.e. if we were
			 	 * at the edge of our consist previously. More complex cases are handled higher
			 	 * in the stack. */
			 	if ((ab->shortening_detected == false) && detect_trivial_shortening(ctx, ab)) {
		 			set_shortening(ctx, ab, true);
			 	} else if ((ab->lengthening_detected == true)
			 		&& is_neighbor_none(&ab->fixed_elected_neighbor)
			 		&& is_neighbor_none(&ab->elected_neighbor)) {
			 		/* special case of the above - if lengthening was set, but the new node
			 		 * has again disappeared, then reset lengthening */
			 		clear_shorten_lengthen(ctx, ab);
			 	}
				break;
			}
			break;
		default:
			next = current;
		break;
	}
	if (current != next) {
		teamd_ttdp_log_infox(ctx->team_devname, "Aggregate state transition %s -> %s",
			AGG_STATE_STRING(current), AGG_STATE_STRING(next));
		move_to_aggregate_state(ctx, ab, next, true);
	} else {
		/* do this to avoid ports sometimes being stuck in DISCARDING on reboot */
		move_to_aggregate_state(ctx, ab, next, false);
	}
	return next;
}

static struct ab_port *ab_port_get(struct ab *ab, struct teamd_port *tdport)
{
	/*
	 * When calling this after teamd_event_watch_register() which is in
	 * ab_init() it is ensured that this will always return valid priv
	 * pointer for an existing port.
	 */
	return teamd_get_first_port_priv_by_creator(tdport, ab);
}

static inline bool ab_is_port_sticky(struct ab *ab, struct teamd_port *tdport)
{
	return ab_port_get(ab, tdport)->cfg.sticky;
}

static int ab_hwaddr_policy_first_port_added(struct teamd_context *ctx,
						struct ab *ab,
						struct teamd_port *tdport) {
	int err;
	teamd_ttdp_log_dbgx(ctx->team_devname, "ab_hwaddr_policy_first_port_added: %d ports, run: %d",
		ctx->port_obj_list_count, ab->hwaddr_policy_first_set);
	// if (ctx->port_obj_list_count == 1) {
	if (ab->hwaddr_policy_first_set++ == 0) {
		/* first! */
		err = team_hwaddr_set(ctx->th, ctx->ifindex, team_get_ifinfo_hwaddr(tdport->team_ifinfo),
			ctx->hwaddr_len);
		if (err) {
			teamd_log_err("%s: Failed to set port hardware address.",
			tdport->ifname);
			return err;
		}
		teamd_ttdp_log_infox(ctx->team_devname, "set team address to that of first member port");
	}
#ifdef SET_PORT_ENABLED_DISABLED
	//team_set_port_enabled(ctx->th, tdport->ifindex, false);
#endif
	return 0;
}

static const struct ab_hwaddr_policy ab_hwaddr_policy_first = {
	.name = "first",
	.port_added = ab_hwaddr_policy_first_port_added,
};

static const struct ab_hwaddr_policy ab_hwaddr_policy_fixed = {
	.name = "fixed",
};


static int ttdp_hwaddr_policy_first_set_get(struct teamd_context *ctx,
				    struct team_state_gsc *gsc,
				    void *priv) {
	struct ab* ab = priv;
	gsc->data.int_val = ab->hwaddr_policy_first_set;
	return 0;
}

static int ab_hwaddr_policy_same_all_hwaddr_changed(struct teamd_context *ctx,
						    struct ab *ab)
{
	struct teamd_port *tdport;
	int err;

	teamd_for_each_tdport(tdport, ctx) {
		err = team_hwaddr_set(ctx->th, tdport->ifindex, ctx->hwaddr,
				      ctx->hwaddr_len);
		if (err) {
			teamd_log_err("%s: Failed to set port hardware address.",
				      tdport->ifname);
			return err;
		}
	}
	return 0;
}

static int ab_hwaddr_policy_same_all_port_added(struct teamd_context *ctx,
						struct ab *ab,
						struct teamd_port *tdport)
{
	int err;

	err = team_hwaddr_set(ctx->th, tdport->ifindex, ctx->hwaddr,
			      ctx->hwaddr_len);
	if (err) {
		teamd_log_err("%s: Failed to set port hardware address.",
			      tdport->ifname);
		return err;
	}
	return 0;
}

static const struct ab_hwaddr_policy ab_hwaddr_policy_same_all = {
	.name = "same_all",
	.hwaddr_changed = ab_hwaddr_policy_same_all_hwaddr_changed,
	.port_added = ab_hwaddr_policy_same_all_port_added,
};

static int ab_hwaddr_policy_by_active_active_set(struct teamd_context *ctx,
						 struct ab *ab,
						 struct teamd_port *tdport)
{
	int err;

	err = team_hwaddr_set(ctx->th, ctx->ifindex,
			      team_get_ifinfo_hwaddr(tdport->team_ifinfo),
			      ctx->hwaddr_len);
	if (err) {
		teamd_log_err("Failed to set team hardware address.");
		return err;
	}
	return 0;
}

static const struct ab_hwaddr_policy ab_hwaddr_policy_by_active = {
	.name = "by_active",
	.active_set = ab_hwaddr_policy_by_active_active_set,
};

static int ab_hwaddr_policy_only_active_hwaddr_changed(struct teamd_context *ctx,
						       struct ab *ab)
{
	struct teamd_port *tdport;
	int err;

	tdport = teamd_get_port(ctx, ab->active_ifindex);
	if (!tdport || !teamd_port_present(ctx, tdport))
		return 0;
	err = team_hwaddr_set(ctx->th, tdport->ifindex, ctx->hwaddr,
			      ctx->hwaddr_len);
	if (err) {
		teamd_log_err("%s: Failed to set port hardware address.",
			      tdport->ifname);
		return err;
	}
	return 0;
}

static int ab_hwaddr_policy_only_active_active_set(struct teamd_context *ctx,
						   struct ab *ab,
						   struct teamd_port *tdport)
{
	int err;

	memcpy(ab->active_orig_hwaddr,
	       team_get_ifinfo_hwaddr(tdport->team_ifinfo),
	       ctx->hwaddr_len);
	err = team_hwaddr_set(ctx->th, tdport->ifindex, ctx->hwaddr,
			      ctx->hwaddr_len);
	if (err) {
		teamd_log_err("%s: Failed to set port hardware address.",
			      tdport->ifname);
		return err;
	}
	return 0;
}

static int ab_hwaddr_policy_only_active_active_clear(struct teamd_context *ctx,
						     struct ab *ab,
						     struct teamd_port *tdport)
{
	int err;

	err = team_hwaddr_set(ctx->th, tdport->ifindex,
			      ab->active_orig_hwaddr,
			      ctx->hwaddr_len);
	if (err) {
		teamd_log_err("%s: Failed to set port hardware address.",
			      tdport->ifname);
		return err;
	}
	return 0;
}

static const struct ab_hwaddr_policy ab_hwaddr_policy_only_active = {
	.name = "only_active",
	.hwaddr_changed = ab_hwaddr_policy_only_active_hwaddr_changed,
	.active_set = ab_hwaddr_policy_only_active_active_set,
	.active_clear = ab_hwaddr_policy_only_active_active_clear,
};

static const struct ab_hwaddr_policy *ab_hwaddr_policy_list[] = {
	&ab_hwaddr_policy_same_all,
	&ab_hwaddr_policy_by_active,
	&ab_hwaddr_policy_only_active,
	&ab_hwaddr_policy_first,
	&ab_hwaddr_policy_fixed,
};

#define AB_HWADDR_POLICY_LIST_SIZE ARRAY_SIZE(ab_hwaddr_policy_list)

static int ab_assign_hwaddr_policy(struct ab *ab,
				   const char *hwaddr_policy_name)
{
	int i = 0;

	if (!hwaddr_policy_name)
		goto found;
	for (i = 0; i < AB_HWADDR_POLICY_LIST_SIZE; i++)
		if (!strcmp(ab_hwaddr_policy_list[i]->name, hwaddr_policy_name))
			goto found;
	return -ENOENT;
found:
	ab->hwaddr_policy = ab_hwaddr_policy_list[i];
	return 0;
}

static int ab_clear_active_port(struct teamd_context *ctx, struct ab *ab,
				struct teamd_port *tdport)
{

	int err;

	ab->active_ifindex = 0;
	if (!tdport || !teamd_port_present(ctx, tdport))
		return 0;
	teamd_ttdp_log_dbgx(ctx->team_devname, "Clearing active port \"%s\".", tdport->ifname);
#ifdef SET_PORT_ENABLED_DISABLED
	err = team_set_port_enabled(ctx->th, tdport->ifindex, false);
	if (err) {
		teamd_log_err("%s: Failed to disable active port.",
			      tdport->ifname);
		return err;
	}
#endif
	if (ab->hwaddr_policy->active_clear) {
		err =  ab->hwaddr_policy->active_clear(ctx, ab, tdport);
		if (err)
			return err;
	}

	return 0;
}

static int ab_set_active_port(struct teamd_context *ctx, struct ab *ab,
			      struct teamd_port *tdport)
{
	int err;
#ifdef SET_PORT_ENABLED_DISABLED
	err = team_set_port_enabled(ctx->th, tdport->ifindex, true);
	if (err) {
		teamd_log_err("%s: Failed to enable active port.",
			      tdport->ifname);
		//return err;
	}
#endif
/* Define MODE_ACTIVEBACKUP to have the behavior below. If not defined, we only
 * change active ports following elections and/or port state changes */
#ifdef MODE_ACTIVEBACKUP
	err = team_set_active_port(ctx->th, tdport->ifindex);
	if (err) {
		teamd_log_err("%s: Failed to set as active port.",
			      tdport->ifname);
		//goto err_set_active_port;
	}
	if (ab->hwaddr_policy->active_set) {
		err =  ab->hwaddr_policy->active_set(ctx, ab, tdport);
		//if (err)
			//goto err_hwaddr_policy_active_set;
	}
	ab->active_ifindex = tdport->ifindex;
	teamd_ttdp_log_infox(ctx->team_devname, "Changed active port to \"%s\".", tdport->ifname);
	return 0;

err_set_active_port:
err_hwaddr_policy_active_set:
#ifdef SET_PORT_ENABLED_DISABLED
	team_set_port_enabled(ctx->th, tdport->ifindex, false);
#endif
	return err;
#else
	return 0;
#endif
}

struct ab_port_state_info {
	struct teamd_port *tdport;
	uint32_t speed;
	uint8_t duplex;
	int prio;
};

static void ab_best_port_check_set(struct teamd_context *ctx,
				   struct ab_port_state_info *best,
				   struct teamd_port *tdport)
{
	struct team_port *port = tdport->team_port;
	uint32_t speed;
	uint8_t duplex;
	int prio;

	if (!teamd_link_watch_port_up(ctx, tdport) || best->tdport == tdport)
		return;

	speed = team_get_port_speed(port);
	duplex = team_get_port_duplex(port);
	prio = teamd_port_prio(ctx, tdport);

	if (!best->tdport || (prio > best->prio) || (speed > best->speed) ||
	    (speed == best->speed && duplex > best->duplex)) {
		best->tdport = tdport;
		best->prio = prio;
		best->speed = speed;
		best->duplex = duplex;
	}
}

static int ab_change_active_port(struct teamd_context *ctx, struct ab *ab,
				 struct teamd_port *active_tdport,
				 struct teamd_port *new_active_tdport)
{
	int err;

	err = ab_clear_active_port(ctx, ab, active_tdport);
	if (err && !TEAMD_ENOENT(err))
		return err;
	err = ab_set_active_port(ctx, ab, new_active_tdport);
	if (err) {
		if (TEAMD_ENOENT(err))
			/* Queue another best port selection */
			teamd_workq_schedule_work(ctx, &ab->link_watch_handler_workq);
		else
			return err;
	}
	return 0;
}

/* Neighbor election. Returns 0 if nothing has changed.
 * One of the cases that we want to support is "staggered bypass relay activation", where the bypass relays responsible
 * for one line are toggled together, and the other line being toggled only after some time. This should, in theory,
 * help with certain issues that occur if all relays are toggled together - for instance if a late node comes up in the
 * middle of a previously-inaugurated train. If not using staggered activation, a total loss of connectivity across the
 * node is likely to happen, depending on how long it takes for the new node to get layer 1 up and running (think
 * Gigabit Ethernet...).
 *
 * Instead, the following should happen:
 * 1. Nodes X and Z are connected using two lines, A and B. Assume that line A is the currently active line.
 * 2. Node Y powers up, in between X and Z. Y's bypass relays are all in the bypass position.
 * 3. When Y is done starting up and ready to participate in TTDP, the relays on one line will be toggled to the
 *  "connect" position (the opposite of "bypass"). Assume for now that this is line A.
 * 4. This creates a short loss of physical and/or logical link between X and Z on line A. X and Z switch to using
 *  line B as the active line.
 * 5. Once the connection comes up on line A, node Y is ready to communicate with X and Z. However, these are still
 *  considered as each others' neighbors, and communicate on line B only.
 * 6. At some point after 3., node Y will toggle the relays on line B. This also causes a short link break, causing
 *  X and Z to switch back to line A.
 * 7. At this point, X and Z start considering Y as their neighbor, and will exchange topology frames and so on.
*/

/* FIXME must ensure that we always change active port, if we get a neighbor change on the currently active port. */
static int elect_neighbor(struct teamd_context *ctx, struct ab *ab, uint8_t *next_port_status) {
	teamd_ttdp_log_infox(ctx->team_devname, "Starting neighbor election... (%d ports)", ctx->port_obj_list_count);
	if (ctx->port_obj_list_count > 0) {
		if ((ctx->port_obj_list_count <= TTDP_MAX_PORTS_PER_TEAM) && (ctx->port_obj_list_count <= 2)) {
			uint8_t* src;
			/* Special case, don't need to do an actual election between 2 ports. Do nothing unless
			 * everyone alive agrees. */
			uint8_t candidate_mac[ETH_ALEN] = {0};
			uint32_t candidate_topocnt = 0;
			uint8_t zero[ETH_ALEN] = {0};
			uint8_t internal_next_port_state[TTDP_MAX_PORTS_PER_TEAM];
			int ignore_candidate = -1;
			int candidate_suggestion;
			for (candidate_suggestion = 0; candidate_suggestion < ctx->port_obj_list_count;
				++candidate_suggestion) {
				bool currently_active = (ab->active_ifindex == candidate_suggestion);
				bool has_changed =
					(memcmp(&(ab->neighbors[candidate_suggestion]),
						&(ab->prev_neighbors[candidate_suggestion]),
						sizeof(ab->neighbors[candidate_suggestion])) == 0)
					&& !is_neighbor_none(&(ab->neighbors[candidate_suggestion]));
				if ((ab->neighbor_agreement_mode == TTDP_NEIGH_AGREE_MODE_SINGLE) && currently_active && has_changed) {
					/* The currently active port has changed its neighbor. This handles cases
					 * where we do not get a link-down event in between neighbors; we need to handle
					 * this by ensuring that we switch to the other neighbor, if available, and take
					 * down the currently active port. */
					ignore_candidate = candidate_suggestion;
					internal_next_port_state[candidate_suggestion] = 1;
					continue;
				}
				int agreement = 1;
				memcpy(candidate_mac, ab->neighbors[candidate_suggestion].neighbor_mac, sizeof(candidate_mac));
				candidate_topocnt = ab->neighbors[candidate_suggestion].neighbor_topocount;
				teamd_ttdp_log_infox(ctx->team_devname, "A new challenger %d, %.2X:%.2X:%.2X:%.2X:%.2X:%.2X, %.8X"
					" appears!",
							candidate_suggestion,
							candidate_mac[0],
							candidate_mac[1],
							candidate_mac[2],
							candidate_mac[3],
							candidate_mac[4],
							candidate_mac[5],
							candidate_topocnt
					);
				int i;
				/* one (itself) will always agree, but this makes for simpler code... */
				for (i = 0; i < ctx->port_obj_list_count; ++i) {
					if (i == ignore_candidate)
						continue;
					if ((memcmp(candidate_mac, ab->neighbors[i].neighbor_mac, sizeof(candidate_mac)) != 0)
						|| (candidate_topocnt != ab->neighbors[i].neighbor_topocount)) {
						/* disagreement - check if the offending MAC is zero, then we can ignore it */
						if (memcmp(ab->neighbors[i].neighbor_mac, zero,
							sizeof(ab->neighbors[i].neighbor_mac)) == 0) {
							/* this port says it doesn't have a neighbor, so we can skip it */
							internal_next_port_state[i] = 1;
							continue;
						} else {
							/* in the special case we're considering here, one non-zero disagreeing
							 * port means the election has failed and we do nothing */
							teamd_ttdp_log_infox(ctx->team_devname, "Election failed! Port %d differs."
								" Not changing elected neighbor.", i);
							agreement = 0;
							internal_next_port_state[i] = 1;
						}
					} else {
						/* this one agrees. */
						teamd_ttdp_log_infox(ctx->team_devname, "Port %d agrees with this candidate.", i);
							internal_next_port_state[i] = 2;
					}
					if (agreement == 0) {
						break;
					}
				}
				if (agreement) {
					goto winner_winner;
				}
			}

			return 0;

		winner_winner:
			memcpy(next_port_status, internal_next_port_state, sizeof(internal_next_port_state));

			src = ab->neighbors[candidate_suggestion].neighbor_uuid;
			teamd_ttdp_log_infox(ctx->team_devname, "Candidate %d has won the election."
				" New neighbor is %.2X:%.2X:%.2X:%.2X:%.2X:%.2X"
				", uuid "
				"%02"PRIx8"%02"PRIx8"%02"PRIx8"%02"PRIx8
				"-"
				"%02"PRIx8"%02"PRIx8
				"-"
				"%02"PRIx8"%02"PRIx8
				"-"
				"%02"PRIx8"%02"PRIx8
				"-"
				"%02"PRIx8"%02"PRIx8"%02"PRIx8"%02"PRIx8"%02"PRIx8"%02"PRIx8
				", topocnt %.8X agreement [%d %d]",
				candidate_suggestion,
				candidate_mac[0],
				candidate_mac[1],
				candidate_mac[2],
				candidate_mac[3],
				candidate_mac[4],
				candidate_mac[5],
				src[0], src[1], src[2], src[3],
				src[4], src[5],
				src[6], src[7],
				src[8], src[9],
				src[10], src[11], src[12], src[13], src[14], src[15],
				candidate_topocnt,
				next_port_status[0], next_port_status[1]
				);

			/* curse you, aliasing rules */
			uint32_t candidate_first;
			uint16_t candidate_last;
			memcpy(&candidate_first, candidate_mac, 4);
			memcpy(&candidate_last, candidate_mac + 4, 2);
			if (candidate_first == 0 && candidate_last == 0) {
				ab->neighbor_is_none = 1;
				teamd_ttdp_log_infox(ctx->team_devname, "Null-MAC set as neighbor.");
			} else {
				ab->neighbor_is_none = 0;
			}

			/* check if a team has reported diagnostic states */
			if (ab->crossed_lines_detected) {
				send_tcnd_crossed_lines_message(ctx, ab);
			}
			if (ab->mixed_consist_orientation_detected) {
				send_tcnd_mixed_consist_orientation_message(ctx, ab);
			}

			/* store winner mac */
			memcpy(ab->elected_neighbor.neighbor_mac, ab->neighbors[candidate_suggestion].neighbor_mac,
				sizeof(ab->elected_neighbor.neighbor_mac));
			/* store winner uuid */
			memcpy(ab->elected_neighbor.neighbor_uuid, ab->neighbors[candidate_suggestion].neighbor_uuid,
				sizeof(ab->elected_neighbor.neighbor_uuid));
			/* store winner topocnt */
			ab->elected_neighbor.neighbor_topocount = ab->neighbors[candidate_suggestion].neighbor_topocount;

			/* check if the new neighbor has a different inhibition flag */
			remote_inhibition_update(ctx, ab);

			/* update previous MAC and/or uuid */
			if (
				(memcmp(ab->elected_neighbor.neighbor_mac, ab->prev_elected_neighbor.neighbor_mac,
				sizeof(ab->elected_neighbor.neighbor_mac)) != 0)
				|| (memcmp(ab->elected_neighbor.neighbor_uuid, ab->prev_elected_neighbor.neighbor_uuid,
				sizeof(ab->elected_neighbor.neighbor_uuid)) != 0)
				)
			{
				memcpy(ab->prev_elected_neighbor.neighbor_mac, ab->elected_neighbor.neighbor_mac,
					sizeof(ab->elected_neighbor.neighbor_mac));
				memcpy(ab->prev_elected_neighbor.neighbor_uuid, ab->elected_neighbor.neighbor_uuid,
					sizeof(ab->elected_neighbor.neighbor_uuid));
				ab->prev_elected_neighbor.neighbor_topocount = ab->elected_neighbor.neighbor_topocount;
				return 1;
			} else {
				return 0;
			}


		} else {
			/* FIXME not yet implemented - implement elections between 3 or 4 ports here */
			return 0;
		}
	} else {
		return 0;
	}
}

static int ab_link_watch_handler_internal(struct teamd_context *ctx, struct ab *ab,
	bool allow_update_aggregate_state) {
	struct teamd_port *tdport;
	struct teamd_port *active_tdport;
	struct ab_port_state_info best;
	int err;
	uint32_t active_ifindex;

	/* this is to allow for recursive calls in some cases. */
	if (allow_update_aggregate_state) {
		/* if we are in FIXED END state, we need some special handling. We don't
		 * add links that have come up to the aggregate, but we do elect neighbors. */
		if (ab->aggregate_status == TTDP_AGG_STATE_FIXED_END) {
			teamd_ttdp_log_infox(ctx->team_devname, "Linkwatch handler update in FIXED END mode...");
			/* Neighbor data is automatically set by my ports. Perform election
		 	 * and notify tcnd if it's changed. */
			if (elect_neighbor(ctx, ab, ab->neighbor_agreement) != 0) {
				/* Notify tcnd that something has changed */
				prepare_tcnd_update_message(ctx, ab);

				//if (ab->silent == TTDP_NOT_SILENT) {
					send_tcnd_update_message(ctx, ab);
				//}
				/* FIXME */
				teamd_ttdp_log_infox(ctx->team_devname, "Sending neighbor update message to TCNd.");
			}

			update_aggregate_state(ctx, ab);
			return 0;
		}
	}

	memset(&best, 0, sizeof(best));
	best.prio = INT_MIN;

	active_tdport = teamd_get_port(ctx, ab->active_ifindex);
	if (active_tdport) {
		teamd_ttdp_log_dbgx(ctx->team_devname, "Current active port: \"%s\" (ifindex \"%d\","
			" prio \"%d\").",
			      active_tdport->ifname, active_tdport->ifindex,
			      teamd_port_prio(ctx, active_tdport));

		err = team_get_active_port(ctx->th, &active_ifindex);
		if (err) {
			teamd_log_err("Failed to get active port.");
			return err;
		}

		/*
		 * When active port went down or it is other than currently set,
		 * clear it and proceed as if none was set in the first place.
		 */
		if (!teamd_link_watch_port_up(ctx, active_tdport) ||
		    active_ifindex != active_tdport->ifindex) {
			err = ab_clear_active_port(ctx, ab, active_tdport);
			if (err)
				return err;
			active_tdport = NULL;
		}
	}

	/* Neighbor data is automatically set by my ports. Perform election
	 * and notify tcnd if it's changed. */
	if (elect_neighbor(ctx, ab, ab->neighbor_agreement) != 0) {
		/* Notify tcnd that something has changed */
		prepare_tcnd_update_message(ctx, ab);

		send_tcnd_update_message(ctx, ab);

		/* FIXME */
		teamd_ttdp_log_infox(ctx->team_devname, "Sending neighbor update message via IPC.");
	}

	teamd_ttdp_log_dbgx(ctx->team_devname, "AGREE mode %d count %d %d", ab->neighbor_agreement_mode,
		ctx->port_obj_list_count, TTDP_MAX_PORTS_PER_TEAM);

	if (ab->neighbor_agreement_mode == TTDP_NEIGH_AGREE_MODE_SINGLE
		&& ctx->port_obj_list_count == TTDP_MAX_PORTS_PER_TEAM) {
		/* Make sure we don't shoot ourselves in the foot here. Don't disable any ports unless
		 * we know that we will still have a neighbor on the other side. */
		int avail = 0;
		for (int i = 0; i < ctx->port_obj_list_count; ++i) {
			if (!is_neighbor_none(&ab->neighbors[i]) && (ab->neighbor_agreement[i] == TTDP_NEIGH_PORT_AGREES))
				avail++;
		}
		teamd_ttdp_log_dbgx(ctx->team_devname, "AGREE avail %d", avail);
		if (avail) {
			for (int i = 0; i < ctx->port_obj_list_count; ++i) {
				uint32_t ifindex = ab->ifindex_by_line[i];
				teamd_ttdp_log_dbgx(ctx->team_devname, "AGREE i %d ifindex %d agree %d heard %d", i, ifindex,
					ab->neighbor_agreement[i], ab->lines_heard[i]);
				/* We currently don't actively set user linkup/down, since this
				 * may conflict with other features. FIXME. */
				switch (ab->neighbor_agreement[i]) {
					case TTDP_NEIGH_PORT_DISAGREES:
						/* this port disagrees - take it down */
					#ifdef SET_PORT_ENABLED_DISABLED
						team_set_port_enabled(ctx->th, ifindex, false);
					#endif
					#ifdef SET_USER_LINK
						team_set_port_user_linkup(ctx->th, ifindex, false);
					#endif
						break;
					case TTDP_NEIGH_PORT_AGREES:
						/* this port agrees - ensure it is up */
						if (ab->lines_heard[i] == true) {
						#ifdef SET_PORT_ENABLED_DISABLED
							team_set_port_enabled(ctx->th, ifindex, true);
						#endif
						#ifdef SET_USER_LINK
							team_set_port_user_linkup(ctx->th, ifindex, true);
						#endif
						} else {
						#ifdef SET_PORT_ENABLED_DISABLED
							team_set_port_enabled(ctx->th, ifindex, false);
						#endif
						#ifdef SET_USER_LINK
							team_set_port_user_linkup(ctx->th, ifindex, false);
						#endif
						}
						break;
					case 0:
					default:
						break;
				}
			}
		} else {
			/* no ports can be used - disable everything */
			for (int i = 0; i < ctx->port_obj_list_count; ++i) {
				uint32_t ifindex = ab->ifindex_by_line[i];
			#ifdef SET_PORT_ENABLED_DISABLED
				team_set_port_enabled(ctx->th, ifindex, false);
			#endif
			}
		}
	}

	/*
	 * Find the best port among all ports. Prefer the currently active
	 * port, if there's any. This is because other port might have the
	 * same prio, speed and duplex. We do not want to change in that case
	 */
	if (active_tdport && teamd_port_present(ctx, active_tdport))
		ab_best_port_check_set(ctx, &best, active_tdport);
	teamd_for_each_tdport(tdport, ctx)
		ab_best_port_check_set(ctx, &best, tdport);

	/* Link status data is automatically set by the lws before this function
	 * is called */
	if (ab->port_statuses_b != ab->port_statuses_b_prev) {
		ab->port_statuses_b_prev = ab->port_statuses_b;
		teamd_ttdp_log_infox(ctx->team_devname, "Sending line status update message to TCNd.");
		send_tcnd_line_status_update_message(ctx, ab);
	}

	if (!best.tdport || best.tdport == active_tdport)
		return 0;

	teamd_ttdp_log_dbgx(ctx->team_devname, "Found best port: \"%s\" (ifindex \"%d\", prio \"%d\").",
		      best.tdport->ifname, best.tdport->ifindex, best.prio);
	if (!active_tdport || !ab_is_port_sticky(ab, active_tdport)) {
		err = ab_change_active_port(ctx, ab, active_tdport,
					    best.tdport);
		if (err)
			return err;
	}
	return 0;
}

static int ab_link_watch_handler(struct teamd_context *ctx, struct ab *ab) {
	return ab_link_watch_handler_internal(ctx, ab, true);
}

static int ab_link_watch_handler_work(struct teamd_context *ctx,
				      struct teamd_workq *workq)
{
	struct ab *ab;

	ab = get_container(workq, struct ab, link_watch_handler_workq);
	return ab_link_watch_handler(ctx, ab);
}

static int ab_event_watch_hwaddr_changed(struct teamd_context *ctx, void *priv)
{
	struct ab *ab = priv;

	if (ab->hwaddr_policy->hwaddr_changed)
		return ab->hwaddr_policy->hwaddr_changed(ctx, ab);
	return 0;
}

static int ab_port_load_config(struct teamd_context *ctx,
			       struct ab_port *ab_port)
{
	const char *port_name = ab_port->tdport->ifname;
	int err;

	err = teamd_config_bool_get(ctx, &ab_port->cfg.sticky,
				    "$.ports.%s.sticky", port_name);
	if (err)
		ab_port->cfg.sticky = AB_DFLT_PORT_STICKY;
	teamd_ttdp_log_dbgx(ctx->team_devname, "%s: Using sticky \"%d\".", port_name,
		      ab_port->cfg.sticky);
	return 0;
}

static int ab_port_added(struct teamd_context *ctx,
			 struct teamd_port *tdport,
			 void *priv, void *creator_priv)
{
	struct ab_port *ab_port = priv;
	struct ab *ab = creator_priv;
	int err;

	ab_port->tdport = tdport;
	err = ab_port_load_config(ctx, ab_port);
	if (err) {
		teamd_log_err("Failed to load port config.");
		return err;
	}
	/* Newly added ports are disabled */
#ifdef SET_PORT_ENABLED_DISABLED
	err = team_set_port_enabled(ctx->th, tdport->ifindex, false);
	if (err) {
		teamd_log_err("%s: Failed to disable port.", tdport->ifname);
		return TEAMD_ENOENT(err) ? 0 : err;
	}
#endif

#ifdef SET_USER_LINK_TEAM_IFACE
	team_set_port_user_linkup_enabled(ctx->th, tdport->ifindex, true);
	team_set_port_user_linkup(ctx->th, tdport->ifindex, false);
#endif

	if (ab->hwaddr_policy->port_added)
		return ab->hwaddr_policy->port_added(ctx, ab, tdport);
	return 0;
}

static void ab_port_removed(struct teamd_context *ctx,
			    struct teamd_port *tdport,
			    void *priv, void *creator_priv)
{
	struct ab *ab = creator_priv;

	ab_link_watch_handler(ctx, ab);
}

static const struct teamd_port_priv ab_port_priv = {
	.init = ab_port_added,
	.fini = ab_port_removed,
	.priv_size = sizeof(struct ab_port),
};

static int ab_event_watch_port_added(struct teamd_context *ctx,
				     struct teamd_port *tdport, void *priv)
{
	struct ab *ab = priv;

#ifdef SET_USER_LINK_TEAM_IFACE
	team_set_port_user_linkup_enabled(ctx->th, tdport->ifindex, true);
	team_set_port_user_linkup(ctx->th, tdport->ifindex, true);
#endif

	return teamd_port_priv_create(tdport, &ab_port_priv, ab);
}

static int ab_event_watch_port_link_changed(struct teamd_context *ctx,
					    struct teamd_port *tdport,
					    void *priv)
{
	struct ab *ab = priv;
	teamd_ttdp_log_dbg(ctx->team_devname, "/// /// PORT LINK CHANGED \\\\\\ \\\\\\");
	/* at this point, the lws should have populated our privdata with relevant info */
	int i;
	for (i = 0; i < TTDP_MAX_PORTS_PER_TEAM; ++i) {
		teamd_ttdp_log_dbg(ctx->team_devname, "member %d ifindex %d neighbor %.2X:%.2X:%.2X:%.2X:%.2X:%.2X%s",
			i, ab->ifindex_by_line[i],
			ab->neighbors[i].neighbor_mac[0],
			ab->neighbors[i].neighbor_mac[1],
			ab->neighbors[i].neighbor_mac[2],
			ab->neighbors[i].neighbor_mac[3],
			ab->neighbors[i].neighbor_mac[4],
			ab->neighbors[i].neighbor_mac[5],
			(ab->ifindex_by_line[i] == tdport->ifindex) ? " ***" : ""
			);
	}
	return ab_link_watch_handler(ctx, priv);
}

static int ab_event_watch_port_changed(struct teamd_context *ctx,
					    struct teamd_port *tdport,
					    void *priv)
{
	struct ab *ab = priv;
	teamd_ttdp_log_dbg(ctx->team_devname, "/// /// PORT CHANGED \\\\\\ \\\\\\");
	/* at this point, the lws should have populated our privdata with relevant info */
	int i;
	for (i = 0; i < TTDP_MAX_PORTS_PER_TEAM; ++i) {
		teamd_ttdp_log_dbg(ctx->team_devname, "member %d ifindex %d neighbor %.2X:%.2X:%.2X:%.2X:%.2X:%.2X%s",
			i, ab->ifindex_by_line[i],
			ab->neighbors[i].neighbor_mac[0],
			ab->neighbors[i].neighbor_mac[1],
			ab->neighbors[i].neighbor_mac[2],
			ab->neighbors[i].neighbor_mac[3],
			ab->neighbors[i].neighbor_mac[4],
			ab->neighbors[i].neighbor_mac[5],
			(ab->ifindex_by_line[i] == tdport->ifindex) ? " ***" : ""
			);
	}

	return ab_link_watch_handler(ctx, priv);
}

static int ab_event_watch_prio_option_changed(struct teamd_context *ctx,
					      struct team_option *option,
					      void *priv)
{
	return ab_link_watch_handler(ctx, priv);
}

static const struct teamd_event_watch_ops ab_event_watch_ops = {
	.hwaddr_changed = ab_event_watch_hwaddr_changed,
	.port_added = ab_event_watch_port_added,
	.port_link_changed = ab_event_watch_port_link_changed,
	.port_changed = ab_event_watch_port_changed,
	.option_changed = ab_event_watch_prio_option_changed,
	.option_changed_match_name = "priority",
};

extern int parse_hwaddr(const char *hwaddr_str, char **phwaddr,
			unsigned int *plen);
extern int parse_uuid(const char* src, uint8_t* dest);
extern void stringify_uuid(uint8_t* src, char* dest);

static int ab_load_config(struct teamd_context *ctx, struct ab *ab)
{
	int err, tmp;
	const char* hwaddr_policy_name;
	const char* tmpstr;

	err = teamd_config_string_get(ctx, &hwaddr_policy_name, "$.runner.hwaddr_policy");
	if (err)
		hwaddr_policy_name = NULL;
	err = ab_assign_hwaddr_policy(ab, hwaddr_policy_name);
	if (err) {
		teamd_log_err("Unknown \"hwaddr_policy\" named \"%s\" passed.",
			      hwaddr_policy_name);
		return err;
	}
	teamd_ttdp_log_dbgx(ctx->team_devname, "Using hwaddr_policy \"%s\".", ab->hwaddr_policy->name);

	err = teamd_config_int_get(ctx, &tmp, "$.runner.direction");
	if (err) {
		teamd_log_err("Error: Failed to get runner direction, aborting");
		return 1;
	}
	ab->direction = tmp;

	err = teamd_config_string_get(ctx, &tmpstr, "$.runner.identity_hwaddr");
	if (err) {
		ab->identity_hwaddr_set = false;
	} else {
		char* tempmac;
		unsigned int templen = 0;
		if (parse_hwaddr(tmpstr, &tempmac, &templen) != 0) {
			teamd_log_warn("Could not parse runner scope identity hwaddr, ignoring");
		} else if (templen != ctx->hwaddr_len) {
			teamd_log_warn("Runner scope identity hwaddr has incorrect length %d, team device has %d, ignoring",
				templen, ctx->hwaddr_len);
			free(tempmac);
		} else {
			teamd_ttdp_log_infox(ctx->team_devname, "Identity hwaddr set (runner).");
			ab->identity_hwaddr_set = true;
			memcpy(ab->identity_hwaddr, tempmac, templen);
			memcpy(ab->identity_hwaddr_str, tmpstr, sizeof(ab->identity_hwaddr_str));
			free(tempmac);
		}
	}

	err = teamd_config_string_get(ctx, &tmpstr, "$.runner.chassis_hwaddr");
	if (err) {
		if (ab->identity_hwaddr_set) {
			teamd_ttdp_log_infox(ctx->team_devname, "Chassis address not set, using identity instead (runner).");
			memcpy(ab->chassis_hwaddr, ab->identity_hwaddr, ctx->hwaddr_len);
			memcpy(ab->chassis_hwaddr_str, ab->identity_hwaddr_str, sizeof(ab->chassis_hwaddr_str));
		} else {
			teamd_log_err("TTDP: Error, could not read chassis_hwaddr, aborting");
			return 1;
		}
	} else {
		char* tempmac;
		unsigned int templen = 0;
		if (parse_hwaddr(tmpstr, &tempmac, &templen) != 0) {
			teamd_log_err("TTDP: Error, could not read chassis_hwaddr, aborting");
			return 1;
		} else if (templen != ctx->hwaddr_len) {
			teamd_log_warn("Chassis hwaddr has incorrect length %d, team device has %d, aborting",
				templen, ctx->hwaddr_len);
			free(tempmac);
			return 1;
		} else {
			teamd_ttdp_log_infox(ctx->team_devname, "Chassis hwaddr set (runner).");
			memcpy(ab->chassis_hwaddr, tempmac, templen);
			memcpy(ab->chassis_hwaddr_str, tmpstr, sizeof(ab->chassis_hwaddr_str));
			free(tempmac);
		}
	}

	err = teamd_config_string_get(ctx, &tmpstr, "$.runner.local_uuid");
	if (err) {
		ab->local_uuid_set = false;
	} else {
		err = parse_uuid(tmpstr, ab->local_uuid);
		if (err) {
			teamd_log_warn("Incorrect UUID string in runner scope, ignoring: %d", err);
		} else {
			teamd_ttdp_log_infox(ctx->team_devname, "Local UUID set (runner).");
			ab->local_uuid_set = true;
			stringify_uuid(ab->local_uuid, ab->local_uuid_str);
		}
	}

	err = teamd_config_int_get(ctx, &tmp, "$.runner.silent");
	if (err) {
		teamd_ttdp_log_infox(ctx->team_devname, "TTDP: Silent setting not given - defaulting to %d", TTDP_NOT_SILENT);
		ab->silent = TTDP_NOT_SILENT;
	} else if (tmp != TTDP_SILENT_NO_OUTPUT && tmp != TTDP_SILENT_NO_OUTPUT_INPUT) {
		teamd_log_warn("TTDP: Incorrect silent setting - use %d or %d; defaulting to %d",
		TTDP_SILENT_NO_OUTPUT, TTDP_SILENT_NO_OUTPUT_INPUT, TTDP_NOT_SILENT);
		ab->silent = TTDP_NOT_SILENT;
	} else {
		teamd_ttdp_log_infox(ctx->team_devname, "TTDP: Setting silent mode to %d", tmp);
		ab->silent = tmp;
	}

	err = teamd_config_int_get(ctx, &tmp, "$.neigh_agree_mode");
	if (err) {
		teamd_ttdp_log_infox(ctx->team_devname, "Neighbor agreement mode not set - defaulting to \"%d\"",
			TTDP_NEIGH_AGREE_MODE_DEFAULT);
		ab->neighbor_agreement_mode = TTDP_NEIGH_AGREE_MODE_DEFAULT;
	} else if (tmp == 0 || tmp == 1) {
		teamd_ttdp_log_infox(ctx->team_devname, "Neighbor agreement mode set to %d", tmp);
		ab->neighbor_agreement_mode = tmp;
	} else {
		teamd_ttdp_log_infox(ctx->team_devname, "Neighbor agreement mode %d not known - defaulting to \"%d\"", tmp,
			TTDP_NEIGH_AGREE_MODE_DEFAULT);
		ab->neighbor_agreement_mode = TTDP_NEIGH_AGREE_MODE_DEFAULT;
	}

	err = teamd_config_string_get(ctx, &tmpstr, "$.runner.vendor_info");
	memset(ab->vendor_info, 0, sizeof(ab->vendor_info));
	if (err) {
	  teamd_ttdp_log_infox(ctx->team_devname, "TTDP: Vendor info not set, defaulting to \"%s\".", TTDP_VENDOR_INFO_DEFAULT);
	  memcpy(ab->vendor_info, TTDP_VENDOR_INFO_DEFAULT, sizeof(ab->vendor_info));
	}
	else {
	  teamd_ttdp_log_infox(ctx->team_devname, "Vendor info set to \"%s\".", tmpstr);
	  memcpy(ab->vendor_info, tmpstr, sizeof(ab->vendor_info));
	}

	return 0;
}

static int ab_state_active_port_get(struct teamd_context *ctx,
				    struct team_state_gsc *gsc,
				    void *priv)
{
	struct ab *ab = priv;
	struct teamd_port *active_tdport;

	active_tdport = teamd_get_port(ctx, ab->active_ifindex);
	gsc->data.str_val.ptr = active_tdport ? active_tdport->ifname : "";
	return 0;
}

struct ab_active_port_set_info {
	struct teamd_workq workq;
	struct ab *ab;
	uint32_t ifindex;
};

static int ab_active_port_set_work(struct teamd_context *ctx,
				   struct teamd_workq *workq)
{
	struct ab_active_port_set_info *info;
	struct ab *ab;
	uint32_t ifindex;
	struct teamd_port *tdport;
	struct teamd_port *active_tdport;

	info = get_container(workq, struct ab_active_port_set_info, workq);
	ab = info->ab;
	ifindex = info->ifindex;
	free(info);
	tdport = teamd_get_port(ctx, ifindex);
	if (!tdport)
		/* Port disappeared in between, ignore */
		return 0;
	active_tdport = teamd_get_port(ctx, ab->active_ifindex);
	return ab_change_active_port(ctx, ab, active_tdport, tdport);
}

static int ab_state_active_port_set(struct teamd_context *ctx,
				    struct team_state_gsc *gsc,
				    void *priv)
{
	struct ab_active_port_set_info *info;
	struct ab *ab = priv;
	struct teamd_port *tdport;

	tdport = teamd_get_port_by_ifname(ctx, (const char *) gsc->data.str_val.ptr);
	if (!tdport)
		return -ENODEV;
	info = malloc(sizeof(*info));
	if (!info)
		return -ENOMEM;
	teamd_workq_init_work(&info->workq, ab_active_port_set_work);
	info->ab = ab;
	info->ifindex = tdport->ifindex;
	teamd_workq_schedule_work(ctx, &info->workq);
	return 0;
}

static int link_state_update_work(struct teamd_context *ctx,
				   struct teamd_workq *workq) {
	struct ab *ab;

	ab = get_container(workq, struct ab, link_state_update_workq);

	teamd_ttdp_log_infox(ctx->team_devname, "Updated port statuses: 1:%s; 2:%s; 3:%s; 4:%s",
		port_state_strings[ab->port_statuses[0]],
		port_state_strings[ab->port_statuses[1]],
		port_state_strings[ab->port_statuses[2]],
		port_state_strings[ab->port_statuses[3]]
		);

	send_tcnd_line_status_update_message(ctx, ab);

	return 0;
}

static int send_link_timeout_update_work(struct teamd_context *ctx,
					struct teamd_workq *workq) {
	struct ab *ab;

	ab = get_container(workq, struct ab, link_timeout_update_workq);

	teamd_ttdp_log_infox(ctx->team_devname, "Updated link timeouts: fast %" PRIu32 " slow %" PRIu32 "",
		ab->latest_line_fast_timeout_ms, ab->latest_line_slow_timeout_ms);

	return send_tcnd_snmp_gen_info(ctx, ab);
}

static int remote_inhibition_update_work(struct teamd_context *ctx,
					struct teamd_workq *workq) {
	struct ab *ab;
/* FIXME elected port does not work here... check individual ports instead and see if they agree */
	ab = get_container(workq, struct ab, remote_inhibition_workq);
	uint8_t remote_inhibition_prev = ab->remote_inhibition_actual;
	if (ab->aggregate_status == TTDP_AGG_STATE_FIXED_END
		|| ab->aggregate_status == TTDP_AGG_STATE_FLOATING_END) {
		if (is_neighbor_none(&(ab->elected_neighbor))) {
			/* zero neighbor has inhibition UNDEFINED per definition */
			ab->remote_inhibition_actual = TTDP_LOGIC_UNDEFINED;
		} else {
			ab->remote_inhibition_actual = TTDP_LOGIC_FALSE;
			for (int i = 0; i < TTDP_MAX_PORTS_PER_TEAM; ++i) {
				if (ab->neighbor_agreement[i] == TTDP_NEIGH_PORT_AGREES) {
					if (ab->neighbors[i].neighbor_inhibition_state == TTDP_LOGIC_TRUE) {
						ab->remote_inhibition_actual = TTDP_LOGIC_TRUE;
						break;
					}
				}
			}
		}
	} else {
		/* if not end node, the value is meaningless */
		ab->remote_inhibition_actual = TTDP_LOGIC_UNDEFINED;
	}
	teamd_ttdp_log_infox(ctx->team_devname, "Calculated remote inhibition: e:%d state:%d %d->%d",
		ab->elected_neighbor.neighbor_inhibition_state,
		ab->aggregate_status,
		remote_inhibition_prev,
		ab->remote_inhibition_actual);
	if (remote_inhibition_prev != ab->remote_inhibition_actual)
		send_tcnd_remote_inhibit_message(ctx, ab);
	return 0;
}

static int ab_state_port_statuses_get(struct teamd_context *ctx,
				    struct team_state_gsc *gsc,
				    void *priv) {
	struct ab *ab = priv;
	snprintf(ab->port_statuses_str, sizeof(ab->port_statuses_str),
		"1:%s; 2:%s; 3:%s; 4:%s",
		port_state_strings[ab->port_statuses[0]],
		port_state_strings[ab->port_statuses[1]],
		port_state_strings[ab->port_statuses[2]],
		port_state_strings[ab->port_statuses[3]]
		);
	gsc->data.str_val.ptr = ab->port_statuses_str;
	return 0;
}

static int ab_neighbor_etbn_mac_get(struct teamd_context *ctx,
				    struct team_state_gsc *gsc,
				    void *priv) {
	struct ab *ab = priv;
	snprintf(ab->elected_neighbor_mac_str, sizeof(ab->elected_neighbor_mac_str),
		"%.2" PRIX8 ":%.2" PRIX8 ":%.2" PRIX8 ":%.2" PRIX8 ":%.2" PRIX8 ":%.2" PRIX8 "",
		ab->elected_neighbor.neighbor_mac[0],
		ab->elected_neighbor.neighbor_mac[1],
		ab->elected_neighbor.neighbor_mac[2],
		ab->elected_neighbor.neighbor_mac[3],
		ab->elected_neighbor.neighbor_mac[4],
		ab->elected_neighbor.neighbor_mac[5]
		);
	gsc->data.str_val.ptr = ab->elected_neighbor_mac_str;
	return 0;
}

static int ab_neighbor_etbn_uuid_get(struct teamd_context *ctx,
				    struct team_state_gsc *gsc,
				    void *priv) {
	struct ab *ab = priv;
	uint8_t* src = ab->elected_neighbor.neighbor_uuid;
	snprintf(ab->elected_neighbor_uuid_str, sizeof(ab->elected_neighbor_uuid_str),
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
	gsc->data.str_val.ptr = ab->elected_neighbor_uuid_str;
	return 0;
}

static int ab_neighbor_etbn_topocnt_get(struct teamd_context *ctx,
				    struct team_state_gsc *gsc,
				    void *priv) {
	struct ab *ab = priv;
	snprintf(ab->elected_neighbor_topocnt_str, sizeof(ab->elected_neighbor_topocnt_str),
		"%.8X", htonl(ab->elected_neighbor.neighbor_topocount));
	gsc->data.str_val.ptr = ab->elected_neighbor_topocnt_str;
	return 0;
}

static int ab_fixed_neighbor_etbn_mac_get(struct teamd_context *ctx,
				    struct team_state_gsc *gsc,
				    void *priv) {
	struct ab *ab = priv;
	snprintf(ab->fixed_elected_neighbor_mac_str, sizeof(ab->fixed_elected_neighbor_mac_str),
		"%.2" PRIX8 ":%.2" PRIX8 ":%.2" PRIX8 ":%.2" PRIX8 ":%.2" PRIX8 ":%.2" PRIX8 "",
		ab->fixed_elected_neighbor.neighbor_mac[0],
		ab->fixed_elected_neighbor.neighbor_mac[1],
		ab->fixed_elected_neighbor.neighbor_mac[2],
		ab->fixed_elected_neighbor.neighbor_mac[3],
		ab->fixed_elected_neighbor.neighbor_mac[4],
		ab->fixed_elected_neighbor.neighbor_mac[5]
		);
	gsc->data.str_val.ptr = ab->fixed_elected_neighbor_mac_str;
	return 0;
}

static int ab_fixed_neighbor_etbn_uuid_get(struct teamd_context *ctx,
				    struct team_state_gsc *gsc,
				    void *priv) {
	struct ab *ab = priv;
	uint8_t* src = ab->fixed_elected_neighbor.neighbor_uuid;
	snprintf(ab->fixed_elected_neighbor_uuid_str, sizeof(ab->fixed_elected_neighbor_uuid_str),
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
	gsc->data.str_val.ptr = ab->fixed_elected_neighbor_uuid_str;
	return 0;
}

static int ab_fixed_neighbor_etbn_topocnt_get(struct teamd_context *ctx,
				    struct team_state_gsc *gsc,
				    void *priv) {
	struct ab *ab = priv;
	snprintf(ab->fixed_elected_neighbor_topocnt_str, sizeof(ab->fixed_elected_neighbor_topocnt_str),
		"%.8X", htonl(ab->fixed_elected_neighbor.neighbor_topocount));
	gsc->data.str_val.ptr = ab->fixed_elected_neighbor_topocnt_str;
	return 0;
}

static int ttdp_shorten_get(struct teamd_context *ctx,
				    struct team_state_gsc *gsc,
				    void *priv) {
	struct ab* ab = priv;
	gsc->data.bool_val = ab->shortening_detected;
	return 0;
}

static int ttdp_lengthen_get(struct teamd_context *ctx,
				    struct team_state_gsc *gsc,
				    void *priv) {
	struct ab* ab = priv;
	gsc->data.bool_val = ab->lengthening_detected;
	return 0;
}

static int ttdp_aggregate_state_get(struct teamd_context *ctx,
				    struct team_state_gsc *gsc,
				    void *priv) {
	struct ab* ab = priv;
	if ((ab->aggregate_status < 0) || (ab->aggregate_status > TTDP_AGG_STATE_MAX)) {
		/* strange value, reset */
		ab->aggregate_status = TTDP_AGG_STATE_DEFAULT;
	}

	gsc->data.str_val.ptr = agg_state_strings[ab->aggregate_status];
	return 0;
}

static int ab_chassis_hwaddr_get(struct teamd_context *ctx,
				    struct team_state_gsc *gsc,
				    void *priv) {
	struct ab* ab = priv;
	gsc->data.str_val.ptr = ab->chassis_hwaddr_str;
	return 0;
}

static int ab_state_port_statuses_b_get(struct teamd_context *ctx,
				    struct team_state_gsc *gsc,
				    void *priv) {
	struct ab *ab = priv;
	gsc->data.int_val = ab->port_statuses_b;
	return 0;
}

static int ttdp_runner_noop_setter(struct teamd_context *ctx,
				    struct team_state_gsc *gsc,
				    void *priv) {
	return 0;
}

/* functions affecting the aggregate state machine */
static int ttdp_topology_stop_set(struct teamd_context *ctx,
				    struct team_state_gsc *gsc,
				    void *priv) {
	struct ab *ab = priv;
	ab->receiving_topology_frames = false;
	uint8_t prev = ab->aggregate_status;
	uint8_t next = update_aggregate_state(ctx, ab);
	teamd_ttdp_log_dbgx(ctx->team_devname, "Not getting topologies; state change %d->%d",
		prev, next);
	return 0;
}
static int ttdp_topology_stop_get(struct teamd_context *ctx,
				    struct team_state_gsc *gsc,
				    void *priv) {
	struct ab *ab = priv;
	gsc->data.int_val = (ab->receiving_topology_frames) ? 0 : 1;
	return 0;
}
static int ttdp_topology_start_set(struct teamd_context *ctx,
				    struct team_state_gsc *gsc,
				    void *priv) {
	struct ab *ab = priv;
	ab->receiving_topology_frames = true;
	uint8_t prev = ab->aggregate_status;
	uint8_t next = update_aggregate_state(ctx, ab);
	teamd_ttdp_log_dbgx(ctx->team_devname, "Getting topologies again! state change %d->%d",
		prev, next);
	return 0;
}
static int ttdp_topology_start_get(struct teamd_context *ctx,
				    struct team_state_gsc *gsc,
				    void *priv) {
	struct ab *ab = priv;
	gsc->data.int_val = (ab->receiving_topology_frames) ? 1 : 0;
	return 0;
}
static int ttdp_neighbor_data_req_set(struct teamd_context *ctx,
				    struct team_state_gsc *gsc,
				    void *priv) {
	struct ab *ab = priv;
	teamd_ttdp_log_infox(ctx->team_devname, "Neighbor data update requested by statevar");
	prepare_tcnd_update_message(ctx, ab);
	send_tcnd_update_message(ctx, ab);
	return 0;
}
static int ttdp_etb_topocount_get(struct teamd_context *ctx,
				    struct team_state_gsc *gsc,
				    void *priv) {
	struct ab *ab = priv;
	gsc->data.int_val = ab->etb_topo_counter;
	return 0;
}
static int ttdp_etb_topocount_set(struct teamd_context *ctx,
				    struct team_state_gsc *gsc,
				    void *priv) {
	struct ab *ab = priv;
	ab->etb_topo_counter = (uint32_t)gsc->data.int_val;
	teamd_ttdp_log_dbgx(ctx->team_devname,
		"Set ETB topo count to %#.8x from statevar", ab->etb_topo_counter);
	return 0;
}
static int ttdp_etb_topocount_str_get(struct teamd_context *ctx,
				    struct team_state_gsc *gsc,
				    void *priv) {
	struct ab *ab = priv;
	memset(ab->etb_topo_counter_str, 0, sizeof(ab->etb_topo_counter_str));
	snprintf((char*)(ab->etb_topo_counter_str), sizeof(ab->etb_topo_counter_str)-1, "%#8X", htonl(ab->etb_topo_counter));
	gsc->data.str_val.ptr = (char*)(ab->etb_topo_counter_str);
	return 0;
}
static int ttdp_inaugurated_set(struct teamd_context *ctx,
				    struct team_state_gsc *gsc,
				    void *priv) {
	struct ab *ab = priv;
	ab->inaugurated = gsc->data.bool_val;
	uint8_t prev = ab->aggregate_status;
	uint8_t next = update_aggregate_state(ctx, ab);
	teamd_ttdp_log_infox(ctx->team_devname, "Now considering myself %sinaugurated, state change"
		" %d->%d", (gsc->data.bool_val ? "" : "not "), prev, next);
	return 0;
}
static int ttdp_inaugurated_get(struct teamd_context *ctx,
				    struct team_state_gsc *gsc,
				    void *priv) {
	struct ab *ab = priv;
	gsc->data.bool_val = ab->inaugurated;
	return 0;
}
static int ttdp_agg_state_get(struct teamd_context *ctx,
					struct team_state_gsc *gsc,
					void* priv) {
	struct ab *ab = priv;
	if (ab->is_discarding) {
		gsc->data.str_val.ptr = "DISCARDING";
	} else {
		gsc->data.str_val.ptr = "FORWARDING";
	}
	return 0;
}
static int ttdp_neighbor_agreement_get(struct teamd_context *ctx,
					struct team_state_gsc *gsc,
					void* priv) {
	struct ab *ab = priv;
	snprintf(ab->neighbor_agreement_str, sizeof(ab->neighbor_agreement_str),
		"%1d %1d", ab->neighbor_agreement[0], ab->neighbor_agreement[1]);
	ab->neighbor_agreement_str[sizeof(ab->neighbor_agreement_str)-1] = 0;
	gsc->data.str_val.ptr = ab->neighbor_agreement_str;
	return 0;
}
static int ttdp_neighbor_agreement_mode_get(struct teamd_context *ctx,
					struct team_state_gsc *gsc,
					void* priv) {
	struct ab *ab = priv;
	gsc->data.int_val = ab->neighbor_agreement_mode;
	return 0;
}
static int ttdp_neighbor_agreement_mode_set(struct teamd_context *ctx,
					struct team_state_gsc *gsc,
					void* priv) {
	struct ab *ab = priv;
	if (gsc->data.int_val == 0 || gsc->data.int_val == 1) {
		ab->neighbor_agreement_mode = gsc->data.int_val;
		return 0;
	} else {
		return 1;
	}
}
static int ttdp_neighbor_inhibition_get(struct teamd_context *ctx,
					struct team_state_gsc *gsc,
					void* priv) {
	struct ab *ab = priv;
	gsc->data.int_val = ab->remote_inhibition_actual;
	return 0;
}
static int ttdp_inhibition_local_get(struct teamd_context *ctx,
					struct team_state_gsc *gsc,
					void* priv) {
	struct ab *ab = priv;
	gsc->data.int_val = ab->inhibition_flag_local;
	return 0;
}
static int ttdp_inhibition_local_set(struct teamd_context *ctx,
					struct team_state_gsc *gsc,
					void* priv) {
	struct ab *ab = priv;
	ab->inhibition_flag_local = gsc->data.int_val;
	teamd_ttdp_log_infox(ctx->team_devname, "Set local inhibition flag to %d from statevar",
		ab->inhibition_flag_local);
	update_aggregate_state(ctx, ab);
	return 0;
}
static int ttdp_inhibition_nonlocal_get(struct teamd_context *ctx,
					struct team_state_gsc *gsc,
					void* priv) {
	struct ab *ab = priv;
	gsc->data.int_val = ab->inhibition_flag_any;
	return 0;
}
static int ttdp_inhibition_nonlocal_set(struct teamd_context *ctx,
					struct team_state_gsc *gsc,
					void* priv) {
	struct ab *ab = priv;
	ab->inhibition_flag_any = gsc->data.int_val;
	teamd_ttdp_log_infox(ctx->team_devname, "Set non-local (\"any\") inhibition flag to %d from statevar",
		ab->inhibition_flag_any);
	update_aggregate_state(ctx, ab);
	return 0;
}

static const struct teamd_state_val ab_state_vals[] = {
	/* Currently active port. Only meaningful in activebackup mode. Read-write.
	 */
	{
		.subpath = "active_port",
		.type = TEAMD_STATE_ITEM_TYPE_STRING,
		.getter = ab_state_active_port_get,
		.setter = ab_state_active_port_set,
	},
	/* String explaining the current statuses of all (up to) 4 member ports.
	 * For each port, one of "ERROR", "FALSE", " TRUE" or "UNDEF". Read-only. */
	{
		.subpath = "port_statuses",
		.type = TEAMD_STATE_ITEM_TYPE_STRING,
		.getter = ab_state_port_statuses_get,
		.setter = ttdp_runner_noop_setter,
	},
	/* Combined binary status, in decimal format, of all member ports
	 * as sent on the wire. Read-only. */
	{
		.subpath = "port_statuses_b",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = ab_state_port_statuses_b_get,
		.setter = ttdp_runner_noop_setter,
	},
	/* MAC of the currently elected neighbor, in string format. If no neighbor,
	 * returns "00:00:00:00:00:00". Read-only. */
	{
		.subpath = "neighbor_etbn_mac",
		.type = TEAMD_STATE_ITEM_TYPE_STRING,
		.getter = ab_neighbor_etbn_mac_get,
		.setter = ttdp_runner_noop_setter,
	},
	/* UUID of the current neighbor, in string format using the common UUID
	 * syntax. All zero if no neighbor. Read-only. */
	{
		.subpath = "neighbor_etbn_uuid",
		.type = TEAMD_STATE_ITEM_TYPE_STRING,
		.getter = ab_neighbor_etbn_uuid_get,
		.setter = ttdp_runner_noop_setter,
	},
	/* Elected neighbor's ETB topocount - string representation of hex value.
	 * Read-only. */
	{
		.subpath = "neighbor_etbn_topocnt",
		.type = TEAMD_STATE_ITEM_TYPE_STRING,
		.getter = ab_neighbor_etbn_topocnt_get,
		.setter = ttdp_runner_noop_setter,
	},
	/* MAC of the previously elected and saved neighbor, in string format.
	 * Only meaningful when inhibited; neighbor data is saved on the positive
	 * edge of the inhibition value. If no saved neighbor, returns
	 * "00:00:00:00:00:00". Read-only. */
	{
		.subpath = "old_inaug_neigh_etbn_mac",
		.type = TEAMD_STATE_ITEM_TYPE_STRING,
		.getter = ab_fixed_neighbor_etbn_mac_get,
		.setter = ttdp_runner_noop_setter,
	},
	/* UUID of the previously elected and saved neighbor, in string format,
	 * common UUID syntax.
	 * Only meaningful when inhibited; neighbor data is saved on the positive
	 * edge of the inhibition value. If no saved neighbor, returns all zero.
	 * Read-only. */
	{
		.subpath = "old_inaug_neigh_etbn_uuid",
		.type = TEAMD_STATE_ITEM_TYPE_STRING,
		.getter = ab_fixed_neighbor_etbn_uuid_get,
		.setter = ttdp_runner_noop_setter,
	},
	/* ETB topocount of the previously elected and saved neighbor - see above.
	 * Read-only.  */
	{
		.subpath = "old_neighbor_etbn_topocnt",
		.type = TEAMD_STATE_ITEM_TYPE_STRING,
		.getter = ab_fixed_neighbor_etbn_topocnt_get,
		.setter = ttdp_runner_noop_setter,
	},
	/* Set to true whenever we've detected train shortening on the aggregate
	 * level. Only meaningful when inhibited. Read-only. */
	{
		.subpath = "shortening_detected",
		.type = TEAMD_STATE_ITEM_TYPE_BOOL,
		.getter = ttdp_shorten_get,
		.setter = ttdp_runner_noop_setter,
	},
	/* Returns true whenever we've detected train lengthening on the aggregate
	 * level. Only meaningful when inhibited. Read-only. */
	{
		.subpath = "lengthening_detected",
		.type = TEAMD_STATE_ITEM_TYPE_BOOL,
		.getter = ttdp_lengthen_get,
		.setter = ttdp_runner_noop_setter,
	},
	/* Gets the MAC address used in the mandatory LLDP part of the HELLO frame.
	 * Set in the configuration file and read-only here. */
	{
		.subpath = "chassis_hwaddr",
		.type = TEAMD_STATE_ITEM_TYPE_STRING,
		.getter = ab_chassis_hwaddr_get,
		.setter = ttdp_runner_noop_setter,
	},
	/* Current state of the aggregate, in "topology terms", meaning one of the
	 * following:
	 * - "Floating end",
	 * - "Floating intermediate",
	 * - "Fixed end", or
	 * - "Fixed intermediate".
	 * The "Fixed" states are only applicable when inhibited, while the
	 * "intermediate" or "end" states determine whether we're at the end of the
	 * current train topology. Read-only. */
	{
		.subpath = "ttdp_state",
		.type = TEAMD_STATE_ITEM_TYPE_STRING,
		.getter = ttdp_aggregate_state_get,
	},
	/* Writing anything here lets the runner know that we're not receiving
	 * topology frames anymore, from the direction of this aggregate. This is
	 * useful to determine if we're part of the end node in certain scenarios.
	 * Write-only. */
	{
		.subpath = "poke_topology_stop",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = ttdp_topology_stop_get,
		.setter = ttdp_topology_stop_set,
	},
	/* Writing anything here lets the runner know that we're again receiving
	 * topology frames anymore, from the direction of this aggregate.
	 * Write-only. */
	{
		.subpath = "poke_topology_start",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = ttdp_topology_start_get,
		.setter = ttdp_topology_start_set,
	},
	/* Writing anything here results in an IPC message being sent that contains
	 * the current neighbor MAC (IPC message 0x01). Write-only. */
	{
		.subpath = "poke_neighbor_data_req",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = ttdp_runner_noop_setter,
		.setter = ttdp_neighbor_data_req_set
	},
	/* Read-write, contains the current ETB topocount as calculated higher
	 * up in the stack. This has to be actively set from the outside for
	 * things to work properly. The format is INT, so it will unfortunately
	 * be converted to decimal (but see below). If a value is written here, it
	 * will be used as the current topo counter, but will very likely be
	 * overwritten by the rest of the IEC61375 stack quite soon following the
	 * next re-inauguration.
	 * 
	 * This is how the IEC61375 stack ensures that a correct topocounter is sent
	 * by this code in TTDP HELLO frames. Since the state variable uses the
	 * teamd type TEAMD_STATE_ITEM_TYPE_INT, which is handled as a "long"
	 * internally, special care needs to be taken on architectures where "long"
	 * is 32 bits; in these cases, if the topocount has the highest bit set,
	 * this value is to be set as a signed negative number in decimal form.
	 * Basically, whatever this is set to will be read as a signed long in
	 * decmal format. */
	{
		.subpath = "etb_topocount",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = ttdp_etb_topocount_get,
		.setter = ttdp_etb_topocount_set,
	},
	/* The ETB topocount above, but converted to the common hexadecimal string
	 * format. Read-only. */
	{
		.subpath = "etb_topocount_str",
		.type = TEAMD_STATE_ITEM_TYPE_STRING,
		.getter = ttdp_etb_topocount_str_get,
	},
	/* Writing 'true' or 'false' here results in the runner considering itself
	 * as inaugurated or not inaugurated, respectively. This value comes from
	 * higher up in the IEC61375 stack (it's set once a logical topology has
	 * been agreed and a TND calculated). The value is used to control the
	 * aggregate state machine here, in the runner. Read-write. */
	{
		.subpath = "inaugurated",
		.type = TEAMD_STATE_ITEM_TYPE_BOOL,
		.getter = ttdp_inaugurated_get,
		.setter = ttdp_inaugurated_set,
	},
	/* String, says if the aggregate is in "DISCARDING" or "FORWARDING" mode.
	 * This is related to end node management. Read-only. */
	{
		.subpath = "ttdp_agg_state",
		.type = TEAMD_STATE_ITEM_TYPE_STRING,
		.getter = ttdp_agg_state_get,
	},
	/* Returns a string containing integers, one per aggregate member in order,
	 * with the value '1' if that member port agrees with the currently elected
	 * neighbor, and '0' if that member port is connected to either no neighbor,
	 * or to a neighbor other than the one that won the election. Read-only. */
	{
		.subpath = "neighbor_agreement",
		.type = TEAMD_STATE_ITEM_TYPE_STRING,
		.getter = ttdp_neighbor_agreement_get,
	},
	/* Gets or sets the current neighbor agreement mode value as an integer.
	 * This is currently either 0 or 1, where
	 * 0: "multi", actively take down member ports that disagree with the
	 * currently elected neighbor.
	 * 1: "single", don't touch non-agreeing ports
	 *
	 * For "multi" to work correctly, SET_USER_LINK should be defined.
	 * Read-write. */
	{
		.subpath = "neighbor_agreement_mode",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = ttdp_neighbor_agreement_mode_get,
		.setter = ttdp_neighbor_agreement_mode_set
	},
	/* Returns the value of the elected neighbor's inhibition flag, as read in
	 * their HELLO frames. Uses TTDP logic, 1 is FALSE, 2 is TRUE and 3 is
	 * undefined. Read-only. */
	{
		.subpath = "neighbor_inhibition_antivalent",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = ttdp_neighbor_inhibition_get
	},
	/* Read-write, whether inhibition is requested by the local node. Uses TTDP
	 * logic, 1 is FALSE and 2 is TRUE. Other values invalid. */
	{
		.subpath = "inhibition_local",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = ttdp_inhibition_local_get,
		.setter = ttdp_inhibition_local_set
	},
	/* read-write, whether inhibition is requested by a non-local node. Uses TTDP
	 * logic, 1 is FALSE and 2 is TRUE. Other values invalid. */
	{
		.subpath = "inhibition_nonlocal",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = ttdp_inhibition_nonlocal_get,
		.setter = ttdp_inhibition_nonlocal_set
	},
	{
		.subpath = "first_hwaddr_set",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = ttdp_hwaddr_policy_first_set_get
	}
};

static const struct teamd_state_val ab_state_vg = {
	.subpath = "runner",
	.vals = ab_state_vals,
	.vals_count = ARRAY_SIZE(ab_state_vals),
};

void* line_status_update(void* c, void* a) {
	struct teamd_context* ctx = c;
	struct ab* ab = a;
	teamd_ttdp_log_infox(ctx->team_devname, "Extra line status update!");
	if (c && ab)
		teamd_workq_schedule_work(ctx, &ab->link_state_update_workq);
	return NULL;
}

void* line_timeout_update(void* c, void* a) {
	struct teamd_context* ctx = c;
	struct ab* ab = a;
	teamd_ttdp_log_infox(ctx->team_devname, "Line timeout update");
	if (c && a)
		teamd_workq_schedule_work(ctx, &ab->link_timeout_update_workq);
	return NULL;
}

void* remote_inhibition_update(void* c, void* a) {
	struct teamd_context* ctx = c;
	struct ab* ab = a;
	teamd_ttdp_log_infox(ctx->team_devname, "Extra neighbor inhibition update!");
	if (c && ab)
		teamd_workq_schedule_work(ctx, &ab->remote_inhibition_workq);
	return NULL;
}

static int on_initial_timer(struct teamd_context *ctx, int events, void *priv) {
	/* run until success, max. this many times */
	static int tries = IPC_TRIES_MAX;
	teamd_loop_callback_disable(ctx, ttdp_runner_oneshot_initial_agg_state_name, priv);
	struct ab* ab = (struct ab*)priv;
	line_status_update(ctx, ab);
	int err = 0, err2 = 0;
	if (ab->silent != TTDP_SILENT_NO_OUTPUT_INPUT) {
		/* Don't worry about close(), it's done in socket_open() for us */
		if (socket_open(ctx, ab) == 0) {
			err = send_tcnd_identity_message(ctx, ab);
			teamd_ttdp_log_infox(ctx->team_devname, "Sent identity to TCNd: %d", err);
			if (err < 0)
				err2 += err;

			err = send_tcnd_snmp_gen_info(ctx, ab);
			teamd_ttdp_log_infox(ctx->team_devname, "Sent SNMP gen info to TCNd: %d", err);
			if (err < 0)
				err2 += err;

			// err = send_tcnd_role_message(ctx, priv);
			// teamd_ttdp_log_infox(ctx->team_devname, "Sent role info to TCNd: %d", err);
			// if (err < 0)
			// 	err2 += err;

			err = send_tcnd_line_status_update_message(ctx, priv);
			teamd_ttdp_log_infox(ctx->team_devname, "Sent line status to TCNd: %d", err);
			if (err < 0)
				err2 += err;
		} else {
			err2 = -1;
		}

		if (err2 < 0) {
			if (tries-- <= 0) {
				teamd_log_err("Could not connect to IPC socket after %d attempts - giving up.", IPC_TRIES_MAX);
			} else {
				teamd_loop_callback_enable(ctx, ttdp_runner_oneshot_initial_agg_state_name, priv);
			}
		}
	}
	return 0;
}

static int on_periodic_neighbor_macs_timer(struct teamd_context *ctx, int events, void *priv) {
	/* Periodically send current neighbor status to the rest of the stack */
	struct ab* ab = priv;
	if (!ab)
		return 1;

	teamd_loop_callback_disable(ctx, ttdp_runner_periodic_neighbor_macs_name, ab);
	teamd_workq_schedule_work(ctx, &ab->tcnd_notify_tcnd_workq);
	teamd_loop_callback_enable(ctx, ttdp_runner_periodic_neighbor_macs_name, ab);
	return 0;
}

static int ab_init(struct teamd_context *ctx, void *priv)
{
	struct ab *ab = priv;
	int err;

	/* log to syslog */
	daemon_log_use = DAEMON_LOG_SYSLOG;

	if (!teamd_config_path_exists(ctx, "$.notify_peers.count")) {
		err = teamd_config_int_set(ctx, 1, "$.notify_peers.count");
		if (err) {
			teamd_log_err("Failed to set notify_peers count config value.");
			return err;
		}
	}
	if (!teamd_config_path_exists(ctx, "$.mcast_rejoin.count")) {
		err = teamd_config_int_set(ctx, 1, "$.mcast_rejoin.count");
		if (err) {
			teamd_log_err("Failed to set mcast_rejoin count config value.");
			return err;
		}
	}
	err = ab_load_config(ctx, ab);
	if (err) {
		teamd_log_err("Failed to load config values.");
		return err;
	}
	err = teamd_event_watch_register(ctx, &ab_event_watch_ops, ab);
	if (err) {
		teamd_log_err("Failed to register event watch.");
		return err;
	}
	err = teamd_state_val_register(ctx, &ab_state_vg, ab);
	if (err) {
		teamd_log_err("Failed to register state value group.");
		goto event_watch_unregister;
	}
	teamd_workq_init_work(&ab->link_watch_handler_workq,
			    ab_link_watch_handler_work);
	teamd_workq_init_work(&ab->tcnd_notify_tcnd_workq,
				send_tcnd_update_message_work);
	teamd_workq_init_work(&ab->link_state_update_workq,
				link_state_update_work);
	teamd_workq_init_work(&ab->remote_inhibition_workq,
				remote_inhibition_update_work);
	teamd_workq_init_work(&ab->link_timeout_update_workq,
				send_link_timeout_update_work);

	memset(ab->port_statuses, 3, 4);
	strcpy(ab->tcnd_sock_filename, "/tmp/tcnd.sock");
	ab->tcnd_sockfd = 0;
	ab->etb_topo_counter = 0xFFFFFFFF;
	ab->port_statuses_b = 0xFF;
	ab->inhibition_flag_local = 0;
	ab->inhibition_flag_any = 2;
	ab->inhibition_flag_neighbor = 0;
	ab->inhibition_flag_remote_consist = 0;
	ab->aggregate_status = TTDP_AGG_STATE_DEFAULT;
	ab->remote_inhibition_actual = 3;

	memset(ab->neighbor_lines, '-', sizeof(ab->neighbor_lines));

	ab->line_state_update_func = line_status_update;
	ab->line_timeout_value_update_func = line_timeout_update;

	teamd_loop_callback_timer_add_set(ctx,
		ttdp_runner_oneshot_initial_agg_state_name,
		ab,
		on_initial_timer,
		&ttdp_runner_oneshot_timer,
		&ttdp_runner_oneshot_timer
		);
	teamd_loop_callback_enable(ctx, ttdp_runner_oneshot_initial_agg_state_name, ab);

	teamd_loop_callback_timer_add_set(ctx,
		ttdp_runner_periodic_neighbor_macs_name,
		ab,
		on_periodic_neighbor_macs_timer,
		&ttdp_runner_periodic_neighbor_macs_timer,
		&ttdp_runner_periodic_neighbor_macs_timer
		);
	// teamd_loop_callback_enable(ctx, ttdp_runner_periodic_neighbor_macs_name, ab);

#ifdef SET_USER_LINK_TEAM_IFACE
	// team_set_port_user_linkup_enabled(ctx->th, ctx->ifindex, true);
	// team_set_port_user_linkup(ctx->th, ctx->ifindex, true);
#endif

	teamd_ttdp_log_infox(ctx->team_devname, "Started.");

	return 0;

event_watch_unregister:
	teamd_event_watch_unregister(ctx, &ab_event_watch_ops, ab);
	return err;
}

static void ab_fini(struct teamd_context *ctx, void *priv)
{
	struct ab *ab = priv;

	teamd_state_val_unregister(ctx, &ab_state_vg, ab);
	teamd_event_watch_unregister(ctx, &ab_event_watch_ops, ab);

	socket_close(ctx, ab);
}

const struct teamd_runner teamd_runner_ttdp = {
	.name			= "ttdp",
#ifdef MODE_ACTIVEBACKUP
	.team_mode_name	= "activebackup",
#else
	.team_mode_name	= "random",
#endif
	.priv_size		= sizeof(struct ab),
	.init			= ab_init,
	.fini			= ab_fini,
};
