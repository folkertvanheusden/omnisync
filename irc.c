#define _BSD_SOURCE
#define _XOPEN_SOURCE
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <sys/select.h>

#include <unistd.h>
#include <sys/types.h>
#if defined(IRIX)
#define _BSD_COMPAT	/* for IRIX */
#include <bstring.h>
#include <sys/time.h>
#endif

#include "gen.h"
#include "error.h"
#include "utils.h"
#include "utils2.h"
#include "log.h"

#define ST_DISCONNECTED	1
#define ST_CONNECTED1	10
#define ST_CONNECTED2	20
#define ST_CONNECTED3	30
#define ST_MAINLOOP	50

int send_irc(int fd, char *what, ...)
{
	char buffer[4096];
	va_list ap;

	va_start(ap, what);
	vsnprintf(buffer, sizeof(buffer), what, ap);
	va_end(ap);

	return WRITE(fd, buffer, strlen(buffer));
}

void remove_line(char *io_buffer, int crlf, int *io_buffer_size)
{
	memmove(io_buffer, &io_buffer[crlf + 2], *io_buffer_size - (crlf + 2));
	*io_buffer_size -= (crlf + 2);
	io_buffer[*io_buffer_size] = 0x00;
}


int parse_irc_timestamp(char *in, double *out_ts)
{
	struct tm stm;
	char *dummy;

	memset(&stm, 0x00, sizeof(stm));

	/* Tuesday January 1 2008 -- 20:59 +01:00 */
	/* Wednesday January 2 2008 -- 18:14:02 */
	dummy = strptime(in, "%A %B %d %Y -- %H:%M:%S", &stm);
	if (!dummy)
		dummy = strptime(in, "%A %B %d %Y -- %H:%M", &stm);
	if (dummy == NULL)
	{
		dolog(LOG_INFO, "parse_irc_timestamp/strptime: Error converting time-string '%s'", in);
		return -1;
	}

	*out_ts = (double)mktime(&stm);
	if (*out_ts == -1)
	{
		dolog(LOG_INFO, "parse_irc_timestamp/mktime: Error converting time-string '%s'", in);
		return -1;
	}

	return 0;
}

/* returns 0 if time command received
 *         1 if logged in successfully
 *        -1 no relevant data
 *        -2 i/o error (e.g. disconnect)
 */
int check_for_irc_time_reply(int fd, double *ts)
{
	char authenticated = 0;
	static char *io_buffer = NULL;
	static int io_buffer_size = 0;
	char buffer[32768];
	int n_read = read(fd, buffer, sizeof(buffer));

	if (n_read > 0)
	{
		/* move data to buffer */
		io_buffer = myrealloc(io_buffer, io_buffer_size + n_read + 1);
		memcpy(&io_buffer[io_buffer_size], buffer, n_read);
		io_buffer_size += n_read;
		io_buffer[io_buffer_size] = 0x00;

		/* see if there's anything to process */
		while(io_buffer_size > 0)
		{
			char *dest = NULL, *p = io_buffer, *dummy, *cmd = NULL, *par = NULL, *par2 = NULL;
			int crlf = find_string_offset(io_buffer, "\r\n");
			if (crlf == -1) break;

			io_buffer[crlf] = 0x00;

			/* get destination from irc */
			if (p[0] == ':')
			{
				dummy = strchr(&p[0], ' ');
				if (dummy)
					*dummy = 0x00;

				dest = &p[1];

				if (dummy)
				{
					p = dummy + 1;
					while(*p == ' ') p++;
				}
			}

			/* get command */
			dummy = strchr(&p[0], ' ');
			if (dummy)
				*dummy = 0x00;
			cmd = &p[0];
			if (dummy)
			{
				p = dummy + 1;
				while(*p == ' ') p++;


				/* get parameters */
				dummy = strchr(&p[0], ':');
				if (dummy)
					*dummy = 0x00;
				par = &p[0];
				if (dummy)
				{
					p = dummy + 1;
					while(*p == ' ') p++;

					/* 2nd parameters */
					par2 = p;
				}
			}

			if (strcmp(cmd, "PING") == 0)
			{
				dolog(LOG_DEBUG, "irc: PING with parameter %s received", par2);

				if (send_irc(fd, "PONG %s", par2) == -1)
				{
					remove_line(io_buffer, crlf, &io_buffer_size);
					return -1;
				}

				dolog(LOG_DEBUG, "irc: PONG was sent");
			}
			/* :irc.xs4all.nl 391 blabla123 irc.xs4all.nl :Tuesday January 1 2008 -- 20:59 +01:00 */
			else if (strcmp(cmd, "391") == 0)
			{
				dolog(LOG_DEBUG, "irc: '391' command received, parameter: %s", par2);

				/* parse date 'par2' to *ts */
				if (parse_irc_timestamp(par2, ts) == 0)
				{
					remove_line(io_buffer, crlf, &io_buffer_size);

					return 0;
				}
				else
				{
					dolog(LOG_INFO, "irc: Cannot parse timestamp '%s'", par2);
				}
			}
			/* logged in succesfull? */
			else if (strcmp(cmd, "001") == 0)
			{
				dolog(LOG_DEBUG, "irc: '001' command received: authenticated");

				authenticated = 1;
			}
			else
			{
				/* ignore */
			}

			remove_line(io_buffer, crlf, &io_buffer_size);
		}
	}
	else	/* read error */
	{
		if (errno != EINTR && errno != EAGAIN)
			return -2;
	}

	if (authenticated)
		return 1;

	return -1;
}

int irc(char *bind_to, char *host, int host_port, char *irc_user, char *irc_pw, int sleep_interval, double *ts_start_recv, double *ts_measurement)
{
	static int fd = -1;
	static int state = ST_DISCONNECTED;
	static time_t last_TIME_command;

	for(;;)
	{
		dolog(LOG_DEBUG, "irc: State: %d", state);

		/* not connected? try once */
		if (fd == -1 || state == ST_DISCONNECTED)
		{
			int throttle_sleep = rand() % sleep_interval;

			dolog(LOG_DEBUG, "irc: Sleeping for %d seconds before reconnect to irc-server %s:%d", throttle_sleep, host, host_port);
			sleep(throttle_sleep);

			last_TIME_command = (time_t)0;

			dolog(LOG_DEBUG, "irc: Connecting...");
			fd = connect_to(bind_to, host, host_port);
			if (fd == -1)
			{
				dolog(LOG_CRIT, "irc: Cannot connect to %s:%d", host, host_port);
				return -1;
			}

			state = ST_CONNECTED1;
		}
		else if (state == ST_CONNECTED1)
		{
			if (send_irc(fd, "NICK %s\r\n", irc_user) == -1)
			{
				close(fd);
				state = ST_DISCONNECTED;
			}
			else
			{
				state = ST_CONNECTED2;
			}
		}
		else if (state == ST_CONNECTED2)
		{
			if (irc_pw)
			{
				if (send_irc(fd, "PASS %s\r\n", irc_pw) == -1)
				{
					close(fd);
					state = ST_DISCONNECTED;
				}
				else
				{
					state = ST_CONNECTED3;
				}
			}
			else
			{
				state = ST_CONNECTED3;
			}
		}
		else if (state == ST_CONNECTED3)
		{
			if (send_irc(fd, "USER %s - %s :OmniSync v" VERSION "\r\n", irc_user, host) == -1)
			{
				close(fd);
				state = ST_DISCONNECTED;
			}
		}
		else if (state == ST_MAINLOOP)
		{
		}

		/* still in disconnect state? try again later */
		if (state == ST_DISCONNECTED)
			break;

		if (state == ST_MAINLOOP)
		{
			/* expecting reaction to USER or TIME */
			for(;;)
			{
				time_t now = time(NULL);
				int time_left = now - last_TIME_command;

				if (time_left >= sleep_interval)
				{
					if (send_irc(fd, "TIME\r\n") == -1)
					{
						close(fd);
						state = ST_DISCONNECTED;
					}
					else
					{
						last_TIME_command = now;
					}

					time_left = sleep_interval;
				}

				if (wait_for_socket(fd, sleep_interval) == 0)
				{
					int rc;

					*ts_start_recv = get_ts();

					rc = check_for_irc_time_reply(fd, ts_measurement);
					if (rc == 0) /* got time reply */
					{
						dolog(LOG_DEBUG, "irc: Got timestamp");
						return 0; /* got valid timestamp */
					}
					else if (rc == -2) /* disconnect */
					{
						dolog(LOG_ERR, "irc: Disconnected?");

						close(fd);
						state = ST_DISCONNECTED;

						return -1; /* got no timestamp */
					}
				}
			}

			error_exit("irc: Cannot/should not happen");
		}
		else
		{
			/* there MIGHT be a reply, like PING or so */
			while (wait_for_socket(fd, 1.0) == 0)
			{
				int rc;

				*ts_start_recv = get_ts();

				rc = check_for_irc_time_reply(fd, ts_measurement);
				if (rc == 0)
				{
					state = ST_MAINLOOP;
					return 0;
				}
				else if (rc == 1)
				{
					state = ST_MAINLOOP;
				}
			}
		}
	}

	return -1;
}
