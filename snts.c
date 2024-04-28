#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "gen.h"
#include "error.h"
#include "utils.h"
#include "utils2.h"
#include "log.h"

#define SNTS_PROTOCOL_VERSION	"1.0"

int snts(char *bind_to, int port, int group, char *allowed_ip, double *ts_start_recv, double *ts)
{
	char io_buffer[4096]; /* in globals.h of sntsd this was set as 200, 4096 is a bit of a margin */
	ssize_t rc;
	char *p[7], *start_p = io_buffer;
	int loop;
	static int fd = -1;

	if (fd == -1)
	{
		fd = udp_socket(bind_to);
		if (fd == -1)
			error_exit("snts: Cannot listen on port %d", port);
	}

	for(;;)
	{
		char *recv_ip;
		struct sockaddr_in from;
		socklen_t from_len = sizeof(from);
		if ((rc = recvfrom(fd, io_buffer, sizeof(io_buffer), 0, (struct sockaddr *)&from, &from_len)) <= 0)
		{
			dolog(LOG_ERR, "snts: Cannot receive UDP packet");
			return -1;
		}

		recv_ip = inet_ntoa(from.sin_addr);
		if ((allowed_ip != NULL && strcmp(recv_ip, allowed_ip) == 0) || allowed_ip == NULL)
			break;

		dolog(LOG_WARNING, "snts: received message from %s while expecting from %s", recv_ip, allowed_ip);
	}

	*ts_start_recv = get_ts();

	io_buffer[rc] = 0x00;

	/* snts 1.0 192.168.64.2 123 timeb 201264 1199197731 */

	memset(p, 0x00, sizeof(p));

	/* split receive buffer into individual fields */
	for(loop=0; loop<7; loop++)
	{
		p[loop] = start_p;

		start_p = strchr(start_p, ' ');
		if (!start_p)
			break;

		*start_p = 0x00;
		start_p++;
	}

	if (!p[0] || strcmp(p[0], "snts") != 0)
	{
		dolog(LOG_INFO, "snts: Not an snts message");
		return -1;
	}

	if (!p[1] || strcmp(p[1], SNTS_PROTOCOL_VERSION) != 0)
	{
		dolog(LOG_INFO, "snts: This version of OmniSync only supports protocol version " SNTS_PROTOCOL_VERSION " of snts.");
		return -1;
	}

	if (!p[3] || atoi(p[3]) != group)
	{
		dolog(LOG_DEBUG, "snts: Ignoring message not for my (%d) group: %s", group, p[3]);
		return -1;
	}

	/* p[2] <- check for correct sender? */

	if (!p[4] || strcmp(p[4], "timeb") != 0)
	{
		dolog(LOG_DEBUG, "snts: Ignoring message of type '%s'", p[4]);
		return -1;
	}

	if (!p[6])
	{
		dolog(LOG_DEBUG, "snts: Field with timestamp missing");
		return -1;
	}

	*ts = atof(p[6]);

	return 0;
}
