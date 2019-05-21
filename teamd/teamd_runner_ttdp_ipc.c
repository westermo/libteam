/*
 *   teamd_lw_ttdp_ipc.c teamd TTDP runner IPC handling
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

#include <sys/un.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/if_ether.h>
#include <netdb.h>
#include <inttypes.h>
#include <linux/netdevice.h>
#include <string.h>
#include <errno.h>

#include "teamd.h"
#include "teamd_workq.h"
#include "teamd_lw_ttdp.h"
#include "teamd_runner_ttdp_ipc.h"
#include "teamd_lag_state_persistence.h"

#define MAX_RECV_BUF_SIZE 128*1024
#define TTDP_IPC_SOCKET_CB_NAME "ttdp_ipc_socket"

#define TEAMNAME_OR_EMPTY(P) ((P)\
	? P : "ttdp-runner")
#define teamd_ttdp_log_info(format, args...) daemon_log(LOG_INFO, format, ## args)
#ifdef DEBUG
#define teamd_ttdp_log_infox(P, format, args...) do {\
		struct timeval _debug_tv;\
		gettimeofday(&_debug_tv, NULL);\
		daemon_log(LOG_INFO, "%s %ld.%ld :" format "\n", TEAMNAME_OR_EMPTY(P), _debug_tv.tv_sec, _debug_tv.tv_usec, ## args);\
	} while (0)
#define teamd_ttdp_log_dbg(P, format, args...) daemon_log(LOG_DEBUG, "%s: " format, TEAMNAME_OR_EMPTY(P), ## args)
#define teamd_ttdp_log_dbgx(P, format, args...) daemon_log(LOG_DEBUG, "%s: " format, TEAMNAME_OR_EMPTY(P), ## args)
#else
#define teamd_ttdp_log_infox(P, format, args...) do {} while (0)
#define teamd_ttdp_log_dbg(P, format, args...) do {} while (0)
#define teamd_ttdp_log_dbgx(P, format, args...) do {} while (0)
#endif

#define teamd_ttdp_log_warnx(P, format, args...) daemon_log(LOG_WARNING, "%s: " format, TEAMNAME_OR_EMPTY(P), ## args)


#define min(x,y)  ({                \
    typeof(x) _min1 = (x);          \
    typeof(y) _min2 = (y);          \
    (void) (&_min1 == &_min2);      \
    _min1 < _min2 ? _min1 : _min2; })

/* FIXME use this variable to control retransmission of identity & SNMP gen info messages if we start
 * before TCNd is ready... */
int initial_data_sent = 0;

int socket_open(struct teamd_context *ctx, void *priv) {
	struct ab *ab = priv;
	struct sockaddr_un target;
	int sockfd = 0, err = 0;
	char errorbuf[256] = {0};
	char* errorstr;

	strcpy(ab->tcnd_sock_filename, "/tmp/tcnd.sock");

	if (ab->tcnd_sockfd != 0) {
		teamd_ttdp_log_infox(ctx->team_devname, "Closing socket first.");
		socket_close(ctx, priv);
	} else {
		teamd_ttdp_log_infox(ctx->team_devname, "Opening TCNd IPC socket to \"%s\"", ab->tcnd_sock_filename);
		sockfd = socket(AF_UNIX, SOCK_STREAM /* SOCK_SEQPACKET*/, 0);
		if (sockfd <= 0) {
			/* using GNU strerror_r */
			errorstr = strerror_r(errno, errorbuf, 256);
			if (errorstr) {
				teamd_ttdp_log_infox(ctx->team_devname, "socket() failed when connecting to TCNd: %s", errorbuf);
			} else {
				teamd_ttdp_log_infox(ctx->team_devname, "socket() failed when connecting to TCNd");
			}
			return 1;
		}

		teamd_ttdp_log_infox(ctx->team_devname, "Got sockfd %d", sockfd);

		/* set to non-blocking */
		int flags = fcntl(sockfd, F_GETFL);
		flags |= O_NONBLOCK;
		err = fcntl(sockfd, F_SETFL, flags);

		if (err != 0) {
			/* using GNU strerror_r */
			errorstr = strerror_r(errno, errorbuf, 256);
			if (errorstr) {
				teamd_ttdp_log_infox(ctx->team_devname, "fcntl() failed when connecting to TCNd: %s", errorbuf);
			} else {
				teamd_ttdp_log_infox(ctx->team_devname, "fcntl() failed when connecting to TCNd");
			}
			return 1;
		}

		/* set addresses */
		target.sun_family = AF_UNIX;
		strncpy(target.sun_path, ab->tcnd_sock_filename, sizeof(target.sun_path) - 1);

		/* connect */
		err = connect(sockfd, &target, sizeof(struct sockaddr_un));

		if (err != 0) {
			/* using GNU strerror_r */
			errorstr = strerror_r(errno, errorbuf, 256);
			if (errorstr) {
				teamd_ttdp_log_infox(ctx->team_devname, "connect() failed when connecting to TCNd: %d %s", err, errorbuf);
			} else {
				teamd_ttdp_log_infox(ctx->team_devname, "connect() failed when connecting to TCNd.");
			}
			/* don't abort here */
		}

		ab->tcnd_sockfd = sockfd;

		if (ab->silent != TTDP_SILENT_NO_OUTPUT_INPUT) {
			err = teamd_loop_callback_fd_add(ctx, TTDP_IPC_SOCKET_CB_NAME, ab, tcnd_socket_read_cb, ab->tcnd_sockfd,
				TEAMD_LOOP_FD_EVENT_READ);

			if (err != 0) {
				/* using GNU strerror_r */
				errorstr = strerror_r(errno, errorbuf, 256);
				if (errorstr) {
					teamd_ttdp_log_infox(ctx->team_devname, "teamd_loop_callback_fd_add() failed when connecting to TCNd: %s", errorbuf);
				} else {
					teamd_ttdp_log_infox(ctx->team_devname, "teamd_loop_callback_fd_add() failed when connecting to TCNd");
				}
			}

			err = teamd_loop_callback_enable(ctx, TTDP_IPC_SOCKET_CB_NAME, ab);

			if (err != 0) {
				/* using GNU strerror_r */
				errorstr = strerror_r(errno, errorbuf, 256);
				if (errorstr) {
					teamd_ttdp_log_infox(ctx->team_devname, "Enabling callback failed when connecting to TCNd: %s", errorbuf);
				} else {
					teamd_ttdp_log_infox(ctx->team_devname, "Enabling callback failed when connecting to TCNd");
				}
				return 1;
			}
		}
	}

	if (initial_data_sent == 0) {
		send_tcnd_identity_message(ctx, priv);
		send_tcnd_snmp_gen_info(ctx, priv);
	}

	return 0;
}

int socket_close(struct teamd_context *ctx, void* priv) {
	teamd_ttdp_log_dbg(ctx->team_devname, "socket_close");
	struct ab *ab = priv;
	int err;
	if (ab->tcnd_sockfd != 0) {
		teamd_loop_callback_del(ctx, TTDP_IPC_SOCKET_CB_NAME, priv);
		err = close(ab->tcnd_sockfd);
		/* unlink(ab->tcnd_sock_filename); */
		ab->tcnd_sockfd = 0;
		return err;
	}
	return 1;
}

static inline uint8_t get_tlv_type(uint8_t* header) {
	return header[0];
}

static inline uint32_t get_tlv_length(uint8_t* header) {
        uint32_t t = *(uint32_t*)(header);
        t = ntohl(t);
        t = t & 0x00FFFFFF;
        return t;
}

static inline int tcnd_socket_check_header(uint8_t* header) {
	uint32_t len;
	uint8_t type = get_tlv_type(header);
	uint32_t expected_len;
	switch (type) {
		case 2:
			expected_len = 4;
			break;
		case 3:
			expected_len = 1;
			break;
		case 4:
			expected_len = 0;
			break;
		case 0x13:
			expected_len = 1;
			break;
		default:
			return 0;
	}
	len = get_tlv_length(header);
	return (len <= (MAX_RECV_BUF_SIZE-4)) && ((expected_len == 0) || (len == expected_len));
}

int handle_message(uint8_t type, uint8_t* payload, uint32_t payload_length,
	struct teamd_context *ctx, void* priv) {
	/* all of these have been moved to teamd-esque state variables instead */

	/* complete message available, consume it */
	struct ab* ab = priv;

	/* Handle the message */
	switch (type) {
		case 0xFF:
			/* noop - explicitly do nothing */
			break;
		case 0x02:
			/* PORTED */
			teamd_ttdp_log_dbg(ctx->team_devname, "Received deprecated IPC message 0x02 (ETB topo counter), ignoring");
			// /* TCNd has a new ETB topo counter */
			// if (payload_length != 4 || (ab == NULL)) {
			// 	return 1;
			// }
			// memcpy(&(ab->etb_topo_counter), payload, 4);
			// teamd_ttdp_log_infox(ctx->team_devname,
			// 	"Set ETB topo count to %#.8x from TCNd", ab->etb_topo_counter);
			// /* ntohl(ab->etb_topo_counter); ??? */
			break;
		case 0x03:
			/* PORTED */
			teamd_ttdp_log_dbg(ctx->team_devname, "Received deprecated IPC message 0x03 (non-local inhibit flag), ignoring");
			// /* TCNd has a new inhibit flag */
			// if (payload_length != 1 || (ab == NULL)) {
			// 	return 1;
			// }
			// ab->inhibition_flag_any = payload[0]; /* 2 is TTDP_TRUE */
			// teamd_ttdp_log_infox(ctx->team_devname, "Set non-local (\"any\") inhibition flag to %d from TCNd",
			// 	payload[0]);
			// update_aggregate_state(ctx, ab);
			break;
		case 0x04:
			/* PORTED */
			teamd_ttdp_log_dbg(ctx->team_devname, "Received deprecated IPC message 0x04 (neighbor update request), ignoring");
			// if (ab == NULL) {
			// 	return 1;
			// }
			// /* TCNd requests a neighbor update */
			// //teamd_workq_schedule_work(ctx, &ab->tcnd_notify_tcnd_workq);
			// prepare_tcnd_update_message(ctx, ab);
			// send_tcnd_update_message(ctx, ab);
			break;
		case 0x13:
			/* PORTED */
			teamd_ttdp_log_dbg(ctx->team_devname, "Received deprecated IPC message 0x13 (local inhibit flag), ignoring");
			// /* TCNd has a new locally set inhibition flag */
			// if (payload_length != 1 || ab == NULL) {
			// 	return 1;
			// }
			// ab->inhibition_flag_local = payload[0];
			// teamd_ttdp_log_infox(ctx->team_devname, "Set local inhibition flag to %d from TCNd",
			// 	payload[0]);
			// update_aggregate_state(ctx, ab);
			break;
		default:
			break;
	}
	/*
	int i;
	for (i = 0; i < err; ++i) {
		fprintf(stderr, "%.2X ", buf[i]);
	}
	fprintf(stderr, "\n");

	fprintf(stderr, "%s", buf);
	*/
	return 0;
}

int tcnd_socket_read_cb(struct teamd_context *ctx, int events, void *priv) {
	struct ab* ab = priv;
	static uint8_t header[4] = {0};
	uint8_t* buf = NULL;
	struct sockaddr_un un_from;
	int err = 0;

	memset(&un_from, 0, sizeof(struct sockaddr_un));

	if (ab->tcnd_sockfd <= 0) {
		/* FIXME err */
		return 0;
	}

	/* peek header */
	err = teamd_recvfrom(ab->tcnd_sockfd, header, 4, MSG_PEEK | MSG_DONTWAIT,
		(struct sockaddr*)&un_from,	sizeof(struct sockaddr_un));

	if (err <= 0) {
		teamd_ttdp_log_infox(ctx->team_devname, "tcnd_socket_read_cb 1: Error %d from recvfrom", err);
		goto failed;
	}

	if ((err > 0) && err < sizeof(header)) {
		/* incomplete message - let it be for now */
		return 0;
	}

	teamd_ttdp_log_dbg(ctx->team_devname, "Message from %s read %d says %d %d %d %d",
		(un_from.sun_path[0] == 0) ? "(NONE)" : un_from.sun_path, err,
		header[0], header[1], header[2], header[3]);

	/* check header contents before we decide to consume it */

	uint8_t type = get_tlv_type(header);
	uint32_t length = get_tlv_length(header);

	if (tcnd_socket_check_header(header) == 0) {
		/* Skip this header */
		err = teamd_recvfrom(ab->tcnd_sockfd, header, 4, MSG_DONTWAIT,
			(struct sockaddr*)&un_from,	sizeof(struct sockaddr_un));
		if (err <= 0) {
			teamd_ttdp_log_infox(ctx->team_devname, "tcnd_socket_read_cb 2: Error %d from recvfrom", err);
		}
		if (length > 0) {
			teamd_ttdp_log_dbg(ctx->team_devname, "Invalid TLV, ignoring it + next %u bytes", length);
			/* Skip this message */
			uint32_t safe;
			int left = length;
			buf = malloc(MAX_RECV_BUF_SIZE);
			while (left > 0) {
				safe = min(left, (int)MAX_RECV_BUF_SIZE);
				err = teamd_recvfrom(ab->tcnd_sockfd, buf, safe, MSG_DONTWAIT, (struct sockaddr*)&un_from,
					sizeof(struct sockaddr_un));
				if (err <= 0) {
					teamd_ttdp_log_infox(ctx->team_devname, "tcnd_socket_read_cb 3: Error %d from recvfrom", err);
				}
				left -= safe;
			}
			free(buf);
			buf = NULL;
		} else {
			teamd_ttdp_log_dbg(ctx->team_devname, "Invalid zero-length TLV");
		}

		return 0;
	}


	/* at this point, header has been read and the message looks interesting. Check if the entire
	 * message is available for reading */
	if (length == 0) {
		teamd_ttdp_log_dbg(ctx->team_devname, "Zero-length message OK.");
		/* consume the header */
		err = teamd_recvfrom(ab->tcnd_sockfd, header, 4, MSG_DONTWAIT,
			(struct sockaddr*)&un_from,	sizeof(struct sockaddr_un));
		if (err <= 0) {
			teamd_ttdp_log_infox(ctx->team_devname, "tcnd_socket_read_cb 4: Error %d from recvfrom", err);
		}

		/* handle zero-length message */
		return handle_message(type, NULL, 0, ctx, priv);
	}


	buf = malloc(length);
	if (buf == NULL) {
		teamd_ttdp_log_warnx(ctx->team_devname, "Could not read TLV: out of memory (need %d)", length);
		return 0;
	}
	err = teamd_recvfrom(ab->tcnd_sockfd, buf, length, MSG_PEEK | MSG_DONTWAIT,
		(struct sockaddr*)&un_from,	sizeof(struct sockaddr_un));
	if (err <= 0) {
		teamd_ttdp_log_infox(ctx->team_devname, "tcnd_socket_read_cb 5: Error %d from recvfrom", err);
	}
	teamd_ttdp_log_dbg(ctx->team_devname, "Read %d bytes, expected %d", err, length);
	if (err < (length)) {
		/* the entire message is not available yet - leave everything */
		free(buf);
		return 0;
	}

	/* both header and message are ok and available - consume */
	err = teamd_recvfrom(ab->tcnd_sockfd, header, 4, MSG_DONTWAIT,
		(struct sockaddr*)&un_from,	sizeof(struct sockaddr_un));
	if (err <= 0) {
		teamd_ttdp_log_infox(ctx->team_devname, "tcnd_socket_read_cb 6: Error %d from recvfrom", err);
	}

	teamd_ttdp_log_dbg(ctx->team_devname, "Read header OK");

	err = teamd_recvfrom(ab->tcnd_sockfd, buf, length, MSG_DONTWAIT,
		(struct sockaddr*)&un_from,	sizeof(struct sockaddr_un));

	teamd_ttdp_log_dbg(ctx->team_devname, "Read message OK");
	if (err <= 0) {
		teamd_ttdp_log_infox(ctx->team_devname, "tcnd_socket_read_cb 7: Error %d from recvfrom", err);
	}

	/* handle message */
	err = handle_message(type, buf, length, ctx, priv);

	free(buf);
	return err;

failed:
	teamd_ttdp_log_infox(ctx->team_devname, "Possible disconnect - closing socket");
	if (buf != NULL)
		free(buf);
	return socket_close(ctx, ab);
}


int send_tcnd_identity_message(struct teamd_context *ctx, void* priv) {
	struct ab *ab = priv;
	if (!(ab->identity_hwaddr_set) || !(ab->local_uuid_set)) {
		teamd_ttdp_log_warnx(ctx->team_devname, "Could not send identity message"
			" to TCNd: not all values configued: (identity hwaddr:%d local uuid:%d)",
			ab->identity_hwaddr_set, ab->local_uuid_set);
		return 1;
	}
	if (ab->tcnd_sockfd > 0) {
		/* 4 bytes header, 6 bytes identity mac, 16 bytes local uuid */
		uint8_t message[4+6+16] = {0, 0, 0, 6+16};
		memcpy(message+4, ab->identity_hwaddr, 6);
		memcpy(message+4+6, ab->local_uuid, 16);
		int err = write(ab->tcnd_sockfd, message, sizeof(message));
		teamd_ttdp_log_infox(ctx->team_devname, "Sent identity message to TCNd: %d", err);
		return err;
	}
	return 2;
}

int send_tcnd_update_message(struct teamd_context *ctx, void* priv) {
	struct ab *ab = priv;

	if (ab->tcnd_sockfd > 0) {
		/*
		fprintf(stderr, "\n\nSending to TCNd: ");
		int i;
		for (i = 0; i < sizeof(ab->tcnd_next_update_message); ++i)	{
			fprintf(stderr, "%.2X ", ab->tcnd_next_update_message[i]);
		}
		fprintf(stderr, "\n");
		*/
		int err = write(ab->tcnd_sockfd, ab->tcnd_next_update_message, sizeof(ab->tcnd_next_update_message));

		teamd_ttdp_log_infox(ctx->team_devname, "Sent update message to TCNd: %d", err);
	} else {
		/* try to reconnect */
		teamd_ttdp_log_infox(ctx->team_devname, "TCNd socket not open, will try to reconnect %s ", __FUNCTION__);
		socket_open(ctx, priv);
		teamd_workq_schedule_work(ctx, &ab->tcnd_notify_tcnd_workq);
	}
	return 0;
}

int send_tcnd_update_message_work(struct teamd_context *ctx,
				      struct teamd_workq *workq) {
	// teamd_ttdp_log_infox(ctx->team_devname, "DELAYED SOCKET SEND");

	struct ab *ab;
	ab = get_container(workq, struct ab, link_watch_handler_workq);
	return lag_state_write_elected_neighbor(ctx, ab);
}

void prepare_tcnd_update_message(struct teamd_context *ctx, struct ab *ab) {
	memset(ab->tcnd_next_update_message, 0, sizeof(ab->tcnd_next_update_message));
	/* type */
	ab->tcnd_next_update_message[0] = 1;
	/* length - first 2 bytes 0 */
	ab->tcnd_next_update_message[3] = 7;
	/* payload */
	ab->tcnd_next_update_message[4] = ab->direction - 1; /* we use 1 and 2, TCNd uses 0 and 1 */
	memcpy((ab->tcnd_next_update_message) + 5,
		ab->elected_neighbor.neighbor_mac, sizeof(ab->elected_neighbor.neighbor_mac));

}

int send_tcnd_line_status_update_message(struct teamd_context *ctx, void* priv) {
	struct ab *ab = priv;
	/* To make sure we don't end uninitialized data, make sure we send
	 * "UNDEFINED" (3) instead of "ERROR" (0). */
	for (int i = 0; i < 4; ++i) {
		if (((ab->port_statuses_b & (0x3 << (2*i))) >> (2*i)) == 0) {
			ab->port_statuses_b |= (0x3 << (2*i));
		}
	}

	/* header + 2 */
	uint8_t message[4+7] = {0x10, 0, 0, 0x07, 0, 0};
	message[4] = ab->direction - 1;
	message[5] = ab->port_statuses_b;

	/* 4 bytes peer connections */
	memset(&(message[6]), 0, 4);
	/* make sure that non-supported lines are set to '-' */
	int i = 0;
	for (i = 0; i < TTDP_MAX_PORTS_PER_TEAM; ++i) {
		message[6+i] = ab->neighbor_lines[i];
	}
	for (; i < 4; ++i) {
		message[6+i] = '-';
	}

	/* 1 byte port statuses */
	if (ab->is_discarding) {
		message[10] = 0xF0;
	} else {
		message[10] = 0xA0;
	}

	if (ab->tcnd_sockfd > 0) {
		int err = write(ab->tcnd_sockfd, message, sizeof(message));
		teamd_ttdp_log_infox(ctx->team_devname, "Sent line status update message to TCNd: %d"
		 " line %d status %02x", err, message[4], message[5]);
		return err;
	} else {
		teamd_ttdp_log_infox(ctx->team_devname, "TCNd socket not open, will try to reconnect %s ", __FUNCTION__);
		socket_open(ctx, priv);
		/* FIXME */
		int err = write(ab->tcnd_sockfd, message, sizeof(message));
		teamd_ttdp_log_infox(ctx->team_devname, "Sent line status update message to TCNd: %d"
		 " line %d status %02x", err, message[4], message[5]);
		return err;
	}
}

int send_tcnd_role_message(struct teamd_context *ctx, struct ab *ab) {
	uint8_t message[4+2] = {0x36, 0, 0, 2};
	message[4] = ab->direction - 1;
	message[5] = ab->aggregate_status;

	if (ab->tcnd_sockfd > 0) {
		int err = write(ab->tcnd_sockfd, message, sizeof(message));
		teamd_ttdp_log_infox(ctx->team_devname, "Sent role update message to TCNd: %d"
		 " direction %d status %d", err, message[4], message[5]);
		return err;
	} else {
		teamd_ttdp_log_infox(ctx->team_devname, "TCNd socket not open, will try to reconnect %s ", __FUNCTION__);
		socket_open(ctx, ab);
		/* FIXME */
		int err = write(ab->tcnd_sockfd, message, sizeof(message));
		teamd_ttdp_log_infox(ctx->team_devname, "Sent role update message to TCNd: %d"
		 " direction %d status %d", err, message[4], message[5]);
		return err;
	}
}

int send_tcnd_shorten_lengthen_message(struct teamd_context *ctx, struct ab *ab) {
	uint8_t message[4+2] = {0x39, 0, 0, 2};
	message[4] = ab->direction - 1;
	message[5] = (ab->shortening_detected) ? 1 : 0;
	message[5] |= (ab->lengthening_detected) ? 2 : 0;

	if (ab->tcnd_sockfd > 0) {
		int err = write(ab->tcnd_sockfd, message, sizeof(message));
		teamd_ttdp_log_infox(ctx->team_devname, "Sent shorten-lengthen message to TCNd: %d"
		 " direction %d status %d", err, message[4], message[5]);
		return err;
	} else {
		teamd_ttdp_log_infox(ctx->team_devname, "TCNd socket not open, will try to reconnect %s ", __FUNCTION__);
		socket_open(ctx, ab);
		/* FIXME */
		int err = write(ab->tcnd_sockfd, message, sizeof(message));
		teamd_ttdp_log_infox(ctx->team_devname, "Sent shorten-lengthen message to TCNd: %d"
		 " direction %d status %d", err, message[4], message[5]);
		return err;
	}
}

int send_tcnd_crossed_lines_message(struct teamd_context *ctx, struct ab *ab) {
	uint8_t message[4+4] = {0x24, 0, 0, 4};
	message[4] = ab->direction - 1;
	message[5] = 1; /* "ETB lines crossed" condition */
	/* two bytes of nothing here */

	if (ab->tcnd_sockfd > 0) {
		int err = write(ab->tcnd_sockfd, message, sizeof(message));
		teamd_ttdp_log_infox(ctx->team_devname, "Sent crossed-lines message to TCNd: %d"
		 " direction %d code %d data %d %d", err, message[4], message[5], message[6], message[7]);
		return err;
	} else {
		teamd_ttdp_log_infox(ctx->team_devname, "TCNd socket not open, will try to reconnect %s ", __FUNCTION__);
		socket_open(ctx, ab);
		/* FIXME */
		int err = write(ab->tcnd_sockfd, message, sizeof(message));
		teamd_ttdp_log_infox(ctx->team_devname, "Sent crossed-lines message to TCNd: %d"
		 " direction %d code %d data %d %d", err, message[4], message[5], message[6], message[7]);
		return err;
	}
}

int send_tcnd_mixed_consist_orientation_message(struct teamd_context *ctx, struct ab *ab) {
	uint8_t message[4+4] = {0x24, 0, 0, 4};
	message[4] = ab->direction - 1;
	message[5] = 2; /* "mixed consist orientation" condition */
	/* two bytes of nothing here */

	if (ab->tcnd_sockfd > 0) {
		int err = write(ab->tcnd_sockfd, message, sizeof(message));
		teamd_ttdp_log_infox(ctx->team_devname, "Sent mixed consist orientation message to TCNd: %d"
		 " direction %d code %d data %d %d", err, message[4], message[5], message[6], message[7]);
		return err;
	} else {
		teamd_ttdp_log_infox(ctx->team_devname, "TCNd socket not open, will try to reconnect %s ", __FUNCTION__);
		socket_open(ctx, ab);
		/* FIXME */
		int err = write(ab->tcnd_sockfd, message, sizeof(message));
		teamd_ttdp_log_infox(ctx->team_devname, "Sent mixed consist orientation message to TCNd: %d"
		 " direction %d code %d data %d %d", err, message[4], message[5], message[6], message[7]);
		return err;
	}
}

int send_tcnd_remote_inhibit_message(struct teamd_context *ctx, struct ab *ab) {
	uint8_t message[4+1] = {0x41, 0, 0, 1, ab->remote_inhibition_actual};

	if (ab->tcnd_sockfd > 0) {
		int err = write(ab->tcnd_sockfd, message, sizeof(message));
		teamd_ttdp_log_infox(ctx->team_devname, "Sent remote inhibit message to TCNd: %d"
		 " remote_inhibit %d", err, message[4]);
		return err;
	} else {
		teamd_ttdp_log_infox(ctx->team_devname, "TCNd socket not open, will try to reconnect %s ", __FUNCTION__);
		socket_open(ctx, ab);
		/* FIXME */
		int err = write(ab->tcnd_sockfd, message, sizeof(message));
		teamd_ttdp_log_infox(ctx->team_devname, "Sent remote inhibit message to TCNd: %d"
		 " remote_inhibit %d", err, message[4]);
		return err;
	}
}

int send_tcnd_snmp_gen_info(struct teamd_context *ctx, struct ab *ab) {
	struct __attribute__((packed)) ttdp_snmp_data_teamd_t {
		uint32_t ttdpSlowTimeout;			/* TTDP HELLO frames slow timeout in ms. */
		uint32_t ttdpFastTimeout;			/* TTDP HELLO frames fast timeout in ms. */
	} ttdp_snmp_data_teamd = {
		.ttdpSlowTimeout = ab->latest_line_slow_timeout_ms,
		.ttdpFastTimeout = ab->latest_line_fast_timeout_ms
	};

	uint8_t message[4+8] = {0x81, 0, 0, 8};
	memcpy(message + 4, &ttdp_snmp_data_teamd, 8);

	if (ab->tcnd_sockfd > 0) {
		int err = write(ab->tcnd_sockfd, message, sizeof(message));
		if (err > 0) {
			teamd_ttdp_log_infox(ctx->team_devname, "Sent SNMP gen info message to TCNd: %d", err);
			initial_data_sent = 1;
			return err;
		}
	}

	teamd_ttdp_log_infox(ctx->team_devname, "TCNd socket error, could not send SNMP data");
	return 1;
}

