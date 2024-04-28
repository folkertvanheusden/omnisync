#define _XOPEN_SOURCE
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>

#include "gen.h"
#include "error.h"
#include "utils.h"
#include "utils2.h"
#include "log.h"

int daytime_to_time_t(char *in, double *out_ts)
{
	struct tm stm;

	memset(&stm, 0x00, sizeof(stm));

	/* Mon Dec 31 12:07:40 2007 */
	if (strptime(in, "%a %b %d %H:%M:%S %Y", &stm) == NULL)
	{
		dolog(LOG_INFO, "daytime_to_time_t/strptime: Error converting time-string '%s'", in);
		return -1;
	}

	*out_ts = (double)mktime(&stm);
	if (*out_ts == -1)
	{
		dolog(LOG_INFO, "daytime_to_time_t/mktime: Error converting time-string '%s'", in);
		return -1;
	}

	return 0;
}

int daytime(char *bind_to, char *host, int host_port, double timeout, char mode, double *ts_start_recv, double *ts)
{
	char io_buffer[128] = { 0 };

	if (mode == IP_UDP)
	{
		socklen_t to_len;
		struct sockaddr_in to;
		int fd = udp_socket(bind_to);
		if (fd == -1)
		{
			dolog(LOG_CRIT, "daytime/UDP: Cannot create UDP socket");
			close(fd);
			return -1;
		}

		if (resolve_host(host, &to) == -1)
		{
			dolog(LOG_ERR, "daytime/UDP: Cannot resolve host %s", host);
			close(fd);
			return -1;
		}

		to.sin_port = htons(host_port);

		if (sendto(fd, "", 0, 0, (struct sockaddr *)&to, sizeof(to)) != 0)
		{
			dolog(LOG_ERR, "daytime/UDP: Cannot send UDP packet to %s:%d", host, host_port);
			close(fd);
			return -1;
		}

		if (wait_for_socket(fd, timeout) == -1)
		{
			dolog(LOG_DEBUG, "daytime/UDP: timeout");
			return -1;
		}

		to_len = sizeof(to);
		if (recvfrom(fd, io_buffer, sizeof(io_buffer), 0, (struct sockaddr *)&to, &to_len) <= 0)
		{
			dolog(LOG_ERR, "daytime/UDP: Cannot receive UDP packet from %s", host);
			close(fd);
			return -1;
		}

		*ts_start_recv = get_ts();

		close(fd);

		if (daytime_to_time_t(io_buffer, ts) == -1)
		{
			dolog(LOG_INFO, "daytime/UDP: error converting timestamp '%s'", io_buffer);
		}

		return 0;
	}
	else if (mode == IP_TCP)
	{
		int fd = connect_to(bind_to, host, host_port);
		if (fd == -1)
		{
			dolog(LOG_ERR, "daytime/TCP: Failed to connect to %s:%d", host, host_port);
			return -1;
		}

		if (wait_for_socket(fd, timeout) == -1)
		{
			dolog(LOG_DEBUG, "daytime/TCP: timeout");
			close(fd);
			return -1;
		}

		if (read(fd, (char *)io_buffer, sizeof(io_buffer)) <= 0)
		{
			dolog(LOG_ERR, "daytime/TCP: Error receiving data from %s", host);
			close(fd);
			return -1;
		}

		*ts_start_recv = get_ts();

		close(fd);

		if (daytime_to_time_t(io_buffer, ts) == -1)
		{
			dolog(LOG_INFO, "daytime/UDP: error converting timestamp '%s'", io_buffer);
		}

		return 0;
	}

	error_exit("daytime: invalid ip mode %d", mode);

	return -1;
}
