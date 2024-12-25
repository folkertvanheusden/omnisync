#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "error.h"
#include "gen.h"
#include "log.h"

#define incopy(a)       *((struct in_addr *)a)

int resolve_host(char *host, struct sockaddr_in *addr)
{
	struct hostent *hostdnsentries;

	hostdnsentries = gethostbyname(host);
	if (hostdnsentries == NULL)
	{
		switch(h_errno)
		{
			case HOST_NOT_FOUND:
				dolog(LOG_ERR, "The specified host is unknown.\n");
				break;

			case NO_ADDRESS:
				dolog(LOG_ERR, "The requested name is valid but does not have an IP address.\n");
				break;

			case NO_RECOVERY:
				dolog(LOG_ERR, "A non-recoverable name server error occurred.\n");
				break;

			case TRY_AGAIN:
				dolog(LOG_ERR, "A temporary error occurred on an authoritative name server. Try again later.\n");
				break;

			default:
				dolog(LOG_ERR, "Could not resolve %s for an unknown reason (%d)\n", host, h_errno);
		}

		return -1;
	}

	/* create address structure */
	addr -> sin_family = hostdnsentries -> h_addrtype;
	addr -> sin_addr = incopy(hostdnsentries -> h_addr_list[0]);

	return 0;
}

int set_tcp_low_latency(int sock)
{
	int flag = 1;

	if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int)) < 0)
		dolog(LOG_ERR, "could not set TCP_NODELAY on socket");

	return 0;
}

int bind_socket_to_address(int fd, char *bindto)
{
	char *temp = strdup(bindto);
	struct sockaddr_in from;
	char *colon = strchr(temp, ':');
	int port = 0;

	if (colon)
	{
		*colon = 0x00;
		port = atoi(colon + 1);
	}

	if (inet_aton(bindto, &from.sin_addr) == 0)
	{
		dolog(LOG_ERR, "bind_socket_to_address: failed converting address");
		free(temp);
		return -1;
	}

	from.sin_family = AF_INET;
	from.sin_port = htons(port);

	if (bind(fd, (struct sockaddr *)&from, sizeof(from)) == -1)
	{
		dolog(LOG_ERR, "bind_socket_to_address: Cannot bind socket");
		free(temp);
		return -1;
	}

	free(temp);

	return 0;
}

int connect_to(char *bindto, char *host, int portnr)
{
	int fd;
	struct sockaddr_in addr;
	int keep_alive = 1;

	/* resolve */
	memset(&addr, 0x00, sizeof(addr));
	resolve_host(host, &addr);
	addr.sin_port = htons(portnr);

	/* connect */
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
	{
		dolog(LOG_ERR, "connect_to: problem creating socket");
		return -1;
	}

	if (bind_socket_to_address(fd, bindto) == -1)
	{
		dolog(LOG_ERR, "connect_to: failed to bind socket");
		return -1;
	}

	if (set_tcp_low_latency(fd) == -1)
	{
		dolog(LOG_ERR, "connect_to: problem setting low latency on socket");
		close(fd);
		return -1;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (char *)&keep_alive, sizeof(keep_alive)) == -1)
	{
		dolog(LOG_ERR, "connect_to: problem setting KEEPALIVE");
		close(fd);
		return -1;
	}

	/* connect to peer */
	if (connect(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr)) == 0)
	{
		/* connection made, return */
		return fd;
	}

	close(fd);

	return -1;
}

int udp_socket(char *bindto)
{
	int fd = socket(PF_INET, SOCK_DGRAM, 0);

	if (bind_socket_to_address(fd, bindto) == -1)
	{
		dolog(LOG_ERR, "udp_socket: failed to bind socket");
		return -1;
	}

	return fd;
}

ssize_t READ(int fd, char *whereto, size_t len)
{
	ssize_t cnt=0;

	while(len>0)
	{
		ssize_t rc;

		rc = read(fd, whereto, len);

		if (rc == -1)
		{
			if (errno != EINTR && errno != EAGAIN)
				error_exit("READ failed");
		}
		else if (rc == 0)
		{
			break;
		}
		else
		{
			whereto += rc;
			len -= rc;
			cnt += rc;
		}
	}

	return cnt;
}

ssize_t WRITE(int fd, char *whereto, size_t len)
{
	ssize_t cnt=0;

	while(len>0)
	{
		ssize_t rc;

		rc = write(fd, whereto, len);

		if (rc == -1)
		{
			if (errno != EINTR && errno != EINPROGRESS && errno != EAGAIN)
				error_exit("WRITE failed");
		}
		else if (rc == 0)
		{
			return -1;
		}
		else
		{
			whereto += rc;
			len -= rc;
			cnt += rc;
		}
	}

	return cnt;
}

int write_pidfile(char *fname)
{
	FILE *fh = fopen(fname, "w");
	if (!fh)
		error_exit("write_pidfile::fopen: failed creating file %s", fname);

	fprintf(fh, "%i", getpid());

	fclose(fh);

	return 0;
}

char * mystrdup(char *in)
{
	char *copy = strdup(in);
	if (!copy)
		error_exit("mystrdup: cannot duplicate string - out of memory?");

	return copy;
}

int find_string_offset(char *str, char *what)
{
	char *dummy = strstr(str, what);
	if (!dummy)
		return -1;

	return (int)(dummy - str);
}

void * myrealloc(void *what, int new_len)
{
	void * newp = realloc(what, new_len);
	if (!newp)
		error_exit("myrealloc: failed to grow memory block %p to %d bytes", what, new_len);

	return newp;
}

void mysleep(int sleep_left)
{
	do
	{
		sleep_left = sleep(sleep_left);

		if (sleep_left > 0 && verbose > 1)
			dolog(LOG_DEBUG, "Early return from sleep (%d) seconds left", sleep_left);
	}
	while(sleep_left > 0);
}

int wait_for_socket(int fd, double timeout)
{

	for(;;)
	{
		int rc;
		fd_set rfds;
		struct timeval tv;

		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);

		tv.tv_sec = (int)timeout;
		tv.tv_usec = (int)((timeout - (double)tv.tv_sec) * 1000000.0);

		rc = select(fd + 1, &rfds, NULL, NULL, &tv);
		if (rc == -1)
		{
			if (errno == EINTR || errno == EAGAIN)
				continue;

			if (errno == EBADF)
				return -1;

			error_exit("wait_for_socket: select() failed");
		}

		if (FD_ISSET(fd, &rfds))
			break;

		return -1;
	}

	return 0;
}
