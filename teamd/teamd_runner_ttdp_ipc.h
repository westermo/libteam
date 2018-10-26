/*
 *   teamd_lw_ttdp_ipc.h teamd TTDP runner IPC handling
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

#include "teamd.h"
#include "teamd_lw_ttdp.h"

extern int initial_data_sent;

int socket_open(struct teamd_context *ctx, void *priv);
int socket_close(struct teamd_context *ctx, void* priv);
void prepare_tcnd_update_message(struct teamd_context *ctx, struct ab *ab);
int send_tcnd_update_message(struct teamd_context *ctx, void* priv);
int send_tcnd_update_message_work(struct teamd_context *ctx,
				      struct teamd_workq *workq);

int tcnd_socket_read_cb(struct teamd_context *ctx, int events, void *priv);

int send_tcnd_line_status_update_message(struct teamd_context *ctx, void* priv);

int send_tcnd_identity_message(struct teamd_context *ctx, void* priv);

int send_tcnd_role_message(struct teamd_context *ctx, struct ab *ab);

int send_tcnd_shorten_lengthen_message(struct teamd_context *ctx, struct ab *ab);

int send_tcnd_crossed_lines_message(struct teamd_context *ctx, struct ab *ab);

int send_tcnd_mixed_consist_orientation_message(struct teamd_context *ctx, struct ab *ab);

int send_tcnd_remote_inhibit_message(struct teamd_context *ctx, struct ab *ab);

int send_tcnd_snmp_gen_info(struct teamd_context *ctx, struct ab *ab);

/* in teamd_runner_ttdp.c */
uint8_t update_aggregate_state(struct teamd_context *ctx,
	struct ab* ab);

