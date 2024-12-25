#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "error.h"
#include "log.h"
#include "utils.h"
#include "utils2.h"

#define PTP_EVENT_MULTICAST_IP_ADDR	"224.0.1.129"
#define PTP_RECV_TRIES			10

int simple_ptp(int port, char *interface_addr, char *allowed_ip, double timeout, double *ts_start_recv, double *ts)
{
	int loop;
	struct ip_mreq imr;
	struct in_addr interfaceAddr, netAddr;
	struct sockaddr_in raddr;
	char *temp = NULL, *colon = NULL;
	socklen_t raddr_len;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd == -1)
		error_exit("simple_ptp: Failed to create socket");

	if (bind_socket_to_address(fd, interface_addr) == -1)
		error_exit("simple_ptp: Failed to bind");

	if (!inet_aton(PTP_EVENT_MULTICAST_IP_ADDR, &netAddr))
		error_exit("simple_ptp: inet_aton(%s) failed", PTP_EVENT_MULTICAST_IP_ADDR);

	temp = strdup(interface_addr);
	colon = strchr(temp, ':');
	if (colon)
		*colon = 0x00;
	if (!inet_aton(temp, &interfaceAddr))
		error_exit("simple_ptp: inet_aton(%s) failed", temp);
	free(temp);

	imr.imr_multiaddr.s_addr = netAddr.s_addr;
	imr.imr_interface.s_addr = interfaceAddr.s_addr;

	/* join multicast group (for receiving) on specified interface */
	if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &imr, sizeof(struct ip_mreq)) == -1)
		error_exit("simple_ptp: Failed to join multicast group (%s)", PTP_EVENT_MULTICAST_IP_ADDR);

	raddr_len = sizeof(raddr);

	for(loop=0; loop<PTP_RECV_TRIES; loop++)
	{
		unsigned long int seconds = 0;
		unsigned long int nanoseconds = 0;
		int rc;
		char *recv_ip;
		char buffer[256];

		if (wait_for_socket(fd, timeout) == -1)
			break;

		rc = recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&raddr, &raddr_len);
		*ts_start_recv = get_ts();

		recv_ip = inet_ntoa(raddr.sin_addr);
		if (allowed_ip != NULL && strcmp(recv_ip, allowed_ip) != 0)
		{
			dolog(LOG_WARNING, "simple_ptp: Ignoring message from %s (expecting %s)", recv_ip, allowed_ip);
			continue;
		}

		if ((buffer[0] & 15) == 0 && (buffer[1] & 15) == 1)
		{
			int cnvloop;

			for(cnvloop=0; cnvloop<4; cnvloop++)
			{
				seconds <<= 8;
				seconds += buffer[40 + cnvloop];
			}
			for(cnvloop=0; cnvloop<4; cnvloop++)
			{
				nanoseconds <<= 8;
				nanoseconds += buffer[44 + cnvloop];
			}

			*ts = (double)seconds + ((double)nanoseconds / 1000000000.0) + 16777216.0 + 256.0;

			close(fd);
			return 0;
		}

		dolog(LOG_DEBUG, "simple_ptp: version is %d and type is %d", buffer[1] & 15, buffer[0] & 15);
	}

	dolog(LOG_WARNING, "simple_ptp: No valid message received in %d tries", PTP_RECV_TRIES);

	close(fd);
	return -1;
}
