/*
 *   teamd_lag_state_persistence.h teamd TTDP runner state persistence
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

#ifndef _TEAMD_LAG_STATE_PERSISTENCE_H_
#define _TEAMD_LAG_STATE_PERSISTENCE_H_

#include <stdio.h>

#include "teamd_lw_ttdp.h"

FILE *open_lag_state_file(const char *team_devname, const char *path, const char *mode);

int lag_state_write_line_status(struct teamd_context *ctx, void *priv);

int lag_state_write_identity(struct teamd_context *ctx, void *priv);

int lag_state_write_aggregate_role(struct teamd_context *ctx, struct ab *ab);

int lag_state_write_diag_crossed_lines_detected(struct teamd_context *ctx, struct ab *ab);

int lag_state_write_diag_mixed_consist_orientation_detected(struct teamd_context *ctx, struct ab *ab);

int lag_state_write_remote_inhibition(struct teamd_context *ctx, struct ab *ab);

int lag_state_write_hello_timeouts(struct teamd_context *ctx, struct ab *ab);

int lag_state_write_elected_neighbor(struct teamd_context *ctx, struct ab *ab);

int lag_state_write_shortening_detected(struct teamd_context *ctx, struct ab *ab);

int lag_state_write_lengthening_detected(struct teamd_context *ctx, struct ab *ab);

#endif // _TEAMD_LAG_STATE_PERSISTENCE_H_

