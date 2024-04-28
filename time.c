#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "gen.h"
#include "error.h"
#include "utils.h"
#include "utils2.h"
#include "log.h"

double time_to_time_t(unsigned char in[4])
{
	unsigned long int epoch;

	epoch = ((time_t)in[0] << 24) +
		(in[1] << 16) +
		(in[2] <<  8) +
		(in[3]      );
	epoch -= 2208988800; /* 'time' returns seconds since january 1, 1900 00:00  */

	return (double)epoch;
}

int gtime(char *bind_to, char *host, int host_port, double timeout, char mode, double *ts_start_recv, double *ts)
{
	unsigned char io_buffer[4];

	if (mode == IP_UDP)
	{
		socklen_t to_len;
		struct sockaddr_in to;
		int fd = udp_socket(bind_to);
		if (fd == -1)
		{
			dolog(LOG_CRIT, "time/UDP: Cannot create UDP socket");
			return -1;
		}

		if (resolve_host(host, &to) == -1)
		{
			dolog(LOG_ERR, "time/UDP: Cannot resolve host %s", host);
			return -1;
		}

		to.sin_port = htons(host_port);

		if (sendto(fd, "", 0, 0, (struct sockaddr *)&to, sizeof(to)) != 0)
		{
			dolog(LOG_ERR, "time/UDP: Cannot send UDP packet to %s:%d", host, host_port);
			return -1;
		}

		if (wait_for_socket(fd, timeout) == -1)
		{
			dolog(LOG_DEBUG, "time/UDP: timeout");
			close(fd);
			return -1;
		}

		*ts_start_recv = get_ts();

		to_len = sizeof(to);
		if (recvfrom(fd, io_buffer, sizeof(io_buffer), 0, (struct sockaddr *)&to, &to_len) != sizeof(io_buffer))
		{
			dolog(LOG_ERR, "time/UDP: Cannot receive UDP packet from %s", host);
			return -1;
		}

		close(fd);

		*ts = time_to_time_t(io_buffer);

		return 0;
	}
	else if (mode == IP_TCP)
	{
		int fd = connect_to(bind_to, host, host_port);
		if (fd == -1)
		{
			dolog(LOG_ERR, "time/TCP: Failed to connect to %s:%d", host, host_port);
			return -1;
		}

		if (wait_for_socket(fd, timeout) == -1)
		{
			dolog(LOG_DEBUG, "time/UDP: timeout");
			close(fd);
			return -1;
		}

		*ts_start_recv = get_ts();

		if (READ(fd, (char *)io_buffer, sizeof(io_buffer)) != 4)
		{
			dolog(LOG_ERR, "time/TCP: Error receiving data from %s", host);
			close(fd);
			return -1;
		}

		close(fd);

		*ts = time_to_time_t(io_buffer);

		return 0;
	}

	error_exit("time: invalid ip mode %d", mode);

	return -1;
}
