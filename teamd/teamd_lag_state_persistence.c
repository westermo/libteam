/*
 *   teamd_lag_state_persistence.c teamd TTDP runner state persistence
 *   Copyright (C) 2019 Westermo
 *   Author: Jacques de Laval <jacques.de.laval@westermo.com>
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

#include <errno.h>
#include <inttypes.h>
#include <linux/limits.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "teamd_lag_state_persistence.h"

#define TEAMNAME_OR_EMPTY(P) ((P)\
	? P : "ttdp-runner")

#define teamd_ttdp_log_warnx(P, format, args...) daemon_log(LOG_WARNING, "%s: " format, TEAMNAME_OR_EMPTY(P), ## args)

#define MAC_FMT_STR "%.2" PRIX8 ":%.2" PRIX8 ":%.2" PRIX8 ":%.2" PRIX8 ":%.2" PRIX8 ":%.2" PRIX8
#define UUID_FMT_STR "%.2" PRIx8 "%.2" PRIx8 "%.2" PRIx8 "%.2" PRIx8  \
					 "-" \
					 "%.2" PRIx8 "%.2" PRIx8  \
					 "-" \
					 "%.2" PRIx8 "%.2" PRIx8  \
					 "-" \
					 "%.2" PRIx8 "%.2" PRIx8  \
					 "-" \
					 "%.2" PRIx8 "%.2" PRIx8 "%.2" PRIx8 "%.2" PRIx8 "%.2" PRIx8 "%.2" PRIx8

#define TEAMD_STATE_PATH "/run/train/lag"

#define TTDP_MAX_LINES_PER_AGG 4

static int mkpathdir(char *file_path, mode_t mode)
{
	char *p;

	for (p = strchr(file_path + 1, '/'); p; p = strchr(p + 1, '/')) {
		*p = '\0';
		if (mkdir(file_path, mode) == -1) {
			if (errno != EEXIST) {
				*p = '/';
				return -1;
			}
		}
		*p = '/';
	}
	return 0;
}

FILE *open_lag_state_file(const char *team_devname, const char *path, const char *mode) {
	char pathname[PATH_MAX] = {'\0'};

	int written = snprintf(pathname, sizeof(pathname), TEAMD_STATE_PATH "/%s/%s", team_devname, path);
	if (written >= sizeof(pathname)) {
		return NULL;
	}

	int err = mkpathdir(pathname, S_IRWXU | (S_IRGRP | S_IXGRP) | (S_IROTH | S_IXOTH));
	if (err < 0) {
		return NULL;
	}

	return fopen(pathname, mode);
}

/**
 * lag_state_write_identity - Persist aggregate identity to state files
 *
 * State files:
 * /run/train/lag/<DEVICE-NAME>/identity/mac - Hardware address (MAC) as string
 * /run/train/lag/<DEVICE-NAME>/identity/uuid - UUID of local consist as string
 */
int lag_state_write_identity(struct teamd_context *ctx, void *priv) {
	struct ab *ab = priv;
	if (!(ab->identity_hwaddr_set) || !(ab->local_uuid_set)) {
		teamd_ttdp_log_warnx(ctx->team_devname, "Could not set identity state"
			" files: not all values configued: (identity hwaddr:%d"
			" local uuid:%d)",
			ab->identity_hwaddr_set, ab->local_uuid_set);
		return 1;
	}

	FILE *state_fp = NULL;

	state_fp = open_lag_state_file(ctx->team_devname, "identity/mac", "w");
	if (!state_fp) {
		return -1;
	}
	fprintf(state_fp, MAC_FMT_STR "\n",
		ab->identity_hwaddr[0],
		ab->identity_hwaddr[1],
		ab->identity_hwaddr[2],
		ab->identity_hwaddr[3],
		ab->identity_hwaddr[4],
		ab->identity_hwaddr[5]);
	fclose(state_fp);

	state_fp = open_lag_state_file(ctx->team_devname, "identity/uuid", "w");
	if (!state_fp) {
		return -1;
	}
	fprintf(state_fp, UUID_FMT_STR "\n",
		ab->local_uuid[0], ab->local_uuid[1], ab->local_uuid[2], ab->local_uuid[3],
		ab->local_uuid[4], ab->local_uuid[5],
		ab->local_uuid[6], ab->local_uuid[7],
		ab->local_uuid[8], ab->local_uuid[9],
		ab->local_uuid[10], ab->local_uuid[11], ab->local_uuid[12], ab->local_uuid[13], ab->local_uuid[14], ab->local_uuid[15]);
	fclose(state_fp);

	return 0;
}

/**
 * lag_state_write_line_status - Persist aggregate line statuses to state files
 *
 * State files:
 * /run/train/lag/<DEVICE-NAME>/line/direction - Direction of aggregated lines, possible values: "0" or "1"
 * /run/train/lag/<DEVICE-NAME>/line/<LINE>/status - Status of line, possible values: "0" (Error), "1" (False), "2" (True) or "3" (Undefined)
 * /run/train/lag/<DEVICE-NAME>/line/<LINE>/connected_neighbor - Connected neighbor line, possible values: "A", "B", "C", "D" or "-" (Undefined)
 * /run/train/lag/<DEVICE-NAME>/line/<LINE>/port_state - Port state, possible values: "0" (Disabled), "2" (Forwarding) or "3" (Discarding)
 * /run/train/lag/<DEVICE-NAME>/line/_commit - A dummy value is written to this file to indicate that aggregate line statuses have changed
 */
int lag_state_write_line_status(struct teamd_context *ctx, void *priv) {
	struct ab *ab = priv;
	FILE *state_fp = NULL;

	state_fp = open_lag_state_file(ctx->team_devname, "line/direction", "w");
	if (!state_fp) {
		return -1;
	}
	fprintf(state_fp, "%"PRIu8"\n", ab->direction - 1);
	fclose(state_fp);

	char path[PATH_MAX] = {'\0'};
	uint8_t port_status;
	for (int i = 0; i < TTDP_MAX_LINES_PER_AGG; i++) {
		memset(path, 0, sizeof(path));
		snprintf(path, sizeof(path), "line/%c/status", 'A' + i);
		state_fp = open_lag_state_file(ctx->team_devname, path, "w");
		if (!state_fp) {
			return -1;
		}
		port_status = ab->port_statuses[i];
		if (port_status == 0) {
			/* To make sure we don't write uninitialized data, make sure we write
			 * "UNDEFINED" (3) instead of "ERROR" (0). */
			port_status = TTDP_LOGIC_UNDEFINED;
		}
		fprintf(state_fp, "%" PRIu8 "\n", port_status);
		fclose(state_fp);

		memset(path, 0, sizeof(path));
		snprintf(path, sizeof(path), "line/%c/connected_neighbor", 'A' + i);
		state_fp = open_lag_state_file(ctx->team_devname, path, "w");
		if (!state_fp) {
			return -1;
		}
		fprintf(state_fp, "%c\n", i >= TTDP_MAX_PORTS_PER_TEAM ? '-' : ab->neighbor_lines[i]);
		fclose(state_fp);

		memset(path, 0, sizeof(path));
		snprintf(path, sizeof(path), "line/%c/port_state", 'A' + i);
		state_fp = open_lag_state_file(ctx->team_devname, path, "w");
		if (!state_fp) {
			return -1;
		}
		if (i >= TTDP_MAX_PORTS_PER_TEAM) {
			fprintf(state_fp, "%d\n", TTDP_PORT_STATE_DISABLED);
		} else if (ab->is_discarding) {
			fprintf(state_fp, "%d\n", TTDP_PORT_STATE_DISCARDING);
		} else {
			fprintf(state_fp, "%d\n", TTDP_PORT_STATE_FORWARDING);
		}
		fclose(state_fp);
	}

	/* After all line status values have been written we write to a separate file
	 * so that any receiver knows that a full line status update is available */
	state_fp = open_lag_state_file(ctx->team_devname, "line/_commit", "w");
	if (!state_fp) {
		return -1;
	}
	fprintf(state_fp, "1\n");
	fclose(state_fp);

	return 0;
}

/**
 * lag_state_write_aggregate_role - Persist aggregate role to state file
 *
 * State files:
 * /run/train/lag/<DEVICE-NAME>/aggregate_role - Aggregate role, possible values: "0" (Floating end), "1" (Floating intermediate), "2" (Fixed end) or "3" (Fixed intermediate)
 */
int lag_state_write_aggregate_role(struct teamd_context *ctx, struct ab *ab) {
	FILE *fp = open_lag_state_file(ctx->team_devname, "aggregate_role", "w");
	if (!fp) {
		return -1;
	}
	fprintf(fp, "%"PRIu8"\n", ab->aggregate_status);
	fclose(fp);
	return 0;
}

/**
 * lag_state_write_diag_crossed_lines_detected - Persist aggregate crossed lines status to state file
 *
 * State files:
 * /run/train/lag/<DEVICE-NAME>/diag/crossed_lines - Crossed lines status, possible values: "0" (False) or "1" (True)
 */
int lag_state_write_diag_crossed_lines_detected(struct teamd_context *ctx, struct ab *ab) {
	FILE *fp = open_lag_state_file(ctx->team_devname, "diag/crossed_lines", "w");
	if (!fp) {
		return -1;
	}
	fprintf(fp, "%d\n", ab->crossed_lines_detected);
	fclose(fp);
	return 0;
}

/**
 * lag_state_write_diag_mixed_consist_orientation_detected - Persist aggregate mixed consist orientation status to state file
 *
 * State files:
 * /run/train/lag/<DEVICE-NAME>/diag/mixed_consist_orientation - Mixed consist orientation status, possible values: "0" (False) or "1" (True)
 */
int lag_state_write_diag_mixed_consist_orientation_detected(struct teamd_context *ctx, struct ab *ab) {
	FILE *fp = open_lag_state_file(ctx->team_devname, "diag/mixed_consist_orientation", "w");
	if (!fp) {
		return -1;
	}
	fprintf(fp, "%d\n", ab->mixed_consist_orientation_detected);
	fclose(fp);
	return 0;
}

/**
 * lag_state_write_remote_inhibition - Persist aggregate remote inhibition status to state file
 *
 * State files:
 * /run/train/lag/<DEVICE-NAME>/remote_inhibition - Remove inhibition, possible values: "1" (False), "2" (True) or "3" (Undefined)
 */
int lag_state_write_remote_inhibition(struct teamd_context *ctx, struct ab *ab) {
	FILE *fp = open_lag_state_file(ctx->team_devname, "remote_inhibition", "w");
	if (!fp) {
		return -1;
	}
	fprintf(fp, "%d\n", ab->remote_inhibition_actual);
	fclose(fp);
	return 0;
}

/**
 * lag_state_write_hello_timeouts - Persist aggregate hello timeout values to state files
 *
 * State files:
 * /run/train/lag/<DEVICE-NAME>/ttdp_hello_timeout/slow - Slow TTDP HELLO timeout as integer
 * /run/train/lag/<DEVICE-NAME>/ttdp_hello_timeout/fast - Fast TTDP HELLO timeout as integer
 */
int lag_state_write_hello_timeouts(struct teamd_context *ctx, struct ab *ab) {
	FILE *fp = open_lag_state_file(ctx->team_devname, "ttdp_hello_timeout/slow", "w");
	if (!fp) {
		return -1;
	}
	fprintf(fp, "%d\n", ab->latest_line_slow_timeout_ms);
	fclose(fp);

	fp = open_lag_state_file(ctx->team_devname, "ttdp_hello_timeout/fast", "w");
	if (!fp) {
		return -1;
	}
	fprintf(fp, "%d\n", ab->latest_line_fast_timeout_ms);
	fclose(fp);

	return 0;
}

/**
 * lag_state_write_elected_neighbor - Persist aggregate elected neighbor to state file
 *
 * State files:
 * /run/train/lag/<DEVICE-NAME>/elected_neighbor/mac - Elected neighbor hardware address (MAC) as string
 */
int lag_state_write_elected_neighbor(struct teamd_context *ctx, struct ab *ab) {
	FILE *fp = open_lag_state_file(ctx->team_devname, "elected_neighbor/mac", "w");
	if (!fp) {
		return -1;
	}
	fprintf(fp, MAC_FMT_STR "\n",
		ab->elected_neighbor.neighbor_mac[0],
		ab->elected_neighbor.neighbor_mac[1],
		ab->elected_neighbor.neighbor_mac[2],
		ab->elected_neighbor.neighbor_mac[3],
		ab->elected_neighbor.neighbor_mac[4],
		ab->elected_neighbor.neighbor_mac[5]);
	fclose(fp);
	return 0;
}

/**
 * lag_state_write_shortening_detected - Persist aggregate shortening status to state file
 *
 * State files:
 * /run/train/lag/<DEVICE-NAME>/shortening_detected - Shortening detected, possible values "0" (False) or "1" (True)
 */
int lag_state_write_shortening_detected(struct teamd_context *ctx, struct ab *ab) {
	FILE *fp = open_lag_state_file(ctx->team_devname, "shortening_detected", "w");
	if (!fp) {
		return -1;
	}
	fprintf(fp, "%d\n", ab->shortening_detected);
	fclose(fp);
	return 0;
}

/**
 * lag_state_write_lengthening_detected - Persist aggregate lengthening status to state file
 *
 * State files:
 * /run/train/lag/<DEVICE-NAME>/lengthening_detected - Lengthening detected, possible values "0" (False) or "1" (True)
 */
int lag_state_write_lengthening_detected(struct teamd_context *ctx, struct ab *ab) {
	FILE *fp = open_lag_state_file(ctx->team_devname, "lengthening_detected", "w");
	if (!fp) {
		return -1;
	}
	fprintf(fp, "%d\n", ab->lengthening_detected);
	fclose(fp);
	return 0;
}
