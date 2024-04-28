/* this code was based on 'icmpquery.c' which I got from
 * http://www.angio.net/security/icmpquery.c
 */

/*
 * icmpquery.c - send and receive ICMP queries for address mask
 *               and current time.
 *
 * Version 1.0.3
 *
 * Copyright 1998, 1999, 2000  David G. Andersen <angio@pobox.com>
 *                                        <danderse@cs.utah.edu>
 *                                        http://www.angio.net/
 *
 * All rights reserved.
 * This information is subject to change without notice and does not
 * represent a commitment on the part of David G. Andersen.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of David G. Andersen may not
 *    be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL DAVID G. ANDERSEN BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include "error.h"
#include "log.h"
#include "utils.h"
#include "utils2.h"

u_short in_cksum(u_short *addr, int len);

void send_icmp(int fd, struct in_addr *whereto)
{
	char io_buffer[1500];
	struct ip *ip_hdr     = (struct ip   *)io_buffer;
	struct icmp *icmp_hdr = (struct icmp *)(ip_hdr + 1);
	struct sockaddr_in dest;

	memset(io_buffer, 0x00, sizeof(io_buffer));

	/* ip_hdr -> ip_src  if 0,  have kernel fill in */
	ip_hdr -> ip_v = 4;		/* Always use ipv4 for now */
	ip_hdr -> ip_hl = sizeof(*ip_hdr) >> 2;
	/* ip_hdr -> ip_tos = 0; memset takes care of this
	 * ip_hdr -> ip_sum = 0;  kernel fills in */
	ip_hdr -> ip_id = htons(4321);
	ip_hdr -> ip_ttl = 255;
	ip_hdr -> ip_p = 1;
	ip_hdr -> ip_len = sizeof(struct ip) + 20;

	icmp_hdr -> icmp_seq = 1;
	icmp_hdr -> icmp_cksum = 0;
	icmp_hdr -> icmp_type = ICMP_TSTAMP;
	icmp_hdr -> icmp_code = 0;

	if (gettimeofday((struct timeval *)(icmp_hdr + 8), NULL) == -1)
		error_exit("icmp_init_packet: gettimeofday failed");

	memset(icmp_hdr + 12, 0x00, 8);

	dest.sin_family = AF_INET;

	ip_hdr -> ip_dst.s_addr = whereto -> s_addr;
	dest.sin_addr           = *whereto;
	icmp_hdr -> icmp_cksum  = 0;
	icmp_hdr -> icmp_cksum  = in_cksum((u_short *)icmp_hdr, 20);

	for(;;)
	{
		int rc = sendto(fd, io_buffer, ip_hdr -> ip_len, 0, (struct sockaddr *)&dest, sizeof(dest));

		if (rc == -1)
		{
			if (errno == EINTR || errno == EAGAIN)
				continue;

			error_exit("icmp_init_packet: sendto() failed");
		}

		break;
	}
}

int receive_icmp_reply(int fd, double timeout, struct in_addr *s_addr_in, double *ts_start_recv, double *ts)
{
	char io_buffer[1500];
	struct ip   *ip_hdr = (struct ip *)io_buffer;
	struct icmp *icmp_hdr;
	socklen_t io_buffer_len;
	int hlen;

	for(;;)
	{
		int rc;

		if (wait_for_socket(fd, timeout) == -1)
		{
			dolog(LOG_DEBUG, "httptime: timeout");
			return -1;
		}

		rc = recvfrom(fd, io_buffer, sizeof(io_buffer), 0, NULL, &io_buffer_len);

		if (rc == -1)
		{
			if (errno == EINTR || errno == EAGAIN)
				continue;

			error_exit("receive_icmp_reply: recvfrom() failed");
		}

		break;
	}

	*ts_start_recv = get_ts();
	*ts = ((int)(get_ts() / 86400.0)) * 86400;

	hlen = ip_hdr -> ip_hl << 2;

	icmp_hdr = (struct icmp *)(io_buffer + hlen);

	if (s_addr_in -> s_addr == ip_hdr -> ip_src.s_addr)
	{
		if (icmp_hdr -> icmp_type == ICMP_TSTAMPREPLY)
		{
			*ts += (double)ntohl(icmp_hdr -> icmp_ttime) / 1000.0;

			return 0;
		}

		dolog(LOG_DEBUG, "receive_icmp_reply: Not a timestamp-reply (%d)", icmp_hdr -> icmp_type);
	}

	dolog(LOG_DEBUG, "receive_icmp_reply: Message not by expected host (%s)", inet_ntoa(ip_hdr -> ip_src));

	return -1;
}

int icmp(char *bind_to, char *host, double timeout, double *ts_start_recv, double *ts)
{
	int fd, rc;
	int on = 1;
	struct sockaddr_in to;

	if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1)
		error_exit("icmp: Failed to create socket");

	if (bind_socket_to_address(fd, bind_to) == -1)
		error_exit("icmp: failed to bind to socket");

	if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) == -1)
		error_exit("icmp: Setsockopt failed");

	if (resolve_host(host, &to) == -1)
		error_exit("icmp: Failed to resolve host %s", host);

	send_icmp(fd, &to.sin_addr);

	rc = receive_icmp_reply(fd, timeout, &to.sin_addr, ts_start_recv, ts);

	close(fd);

	return rc;
}

/*
 * in_cksum --
 *	Checksum routine for Internet Protocol family headers (C Version)
 *      From FreeBSD's ping.c
 */
/*
 * Copyright (c) 1989, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Mike Muuss.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
u_short in_cksum(u_short *addr, int len)
{
	int nleft = len;
	u_short *w = addr;
	int sum = 0;
	u_short answer = 0;

	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(u_char *)(&answer) = *(u_char *)w ;
		sum += answer;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */

	return answer;
}
/* BSD code ends here */
