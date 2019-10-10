/* -*- mode: c; c-file-style: "openbsd" -*- */
/*
 * Copyright (c) 2009 Vincent Bernat <bernat@luffy.cx>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* From LLDPD; modified to remove LLDP dependency */
#include <stdint.h>

uint16_t
frame_checksum(const uint8_t *cp, int len)
{
	unsigned int sum = 0, v = 0;
	int oddbyte = 0;

	/* We compute in network byte order */
	while ((len -= 2) >= 0) {
		sum += *cp++ << 8;
		sum += *cp++;
	}
	if ((oddbyte = len & 1) != 0)
		v = *cp;

	if (oddbyte) {
		sum += v << 8;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += sum >> 16;

	return (0xffff & ~sum);
}
