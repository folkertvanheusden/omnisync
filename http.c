#define _BSD_SOURCE
#define _XOPEN_SOURCE
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <time.h>

#include "gen.h"
#include "error.h"
#include "log.h"
#include "utils.h"
#include "utils2.h"
#include "mssl.h"

int date_to_time_t(char *in, double *out_ts)
{
	struct tm stm;

	memset(&stm, 0x00, sizeof(stm));

	/* Date: Mon, 31 Dec 2007 12:58:23 GMT (IIS)
	   Date: Mon, 31 Dec 2007 12:59:20 GMT (Apache 2.2.6) */
	if (strptime(in, "%a, %d %b %Y %H:%M:%S %Z", &stm) == NULL)
	{
		dolog(LOG_INFO, "date_to_time_t/strptime: Error converting time-string '%s'", in);
		return -1;
	}

	*out_ts = (double)mktime(&stm);
	if (*out_ts == -1)
	{
		dolog(LOG_INFO, "date_to_time_t/mktime: Error converting time-string '%s'", in);
		return -1;
	}

	return 0;
}


int httptime(char *bind_to, char *host, int host_port, double timeout, char *proxy, int proxy_port, char mode, SSL_CTX *ctx, double *ts_start_recv, double *ts)
{
	int global_rc = -1;
	int recv_buffer_in = 0;
	int get_request_len;
	char get_request[4096];
	SSL *ssl_h;
	BIO *s_bio;
	int fd, rc;

	snprintf(get_request, sizeof(get_request), "HEAD http%s://%s:%d/ HTTP/1.0\r\nUser-Agent: OmniSync v" VERSION "\r\n\r\n", mode == HTTPS?"s":"", host, host_port);
	get_request_len = strlen(get_request);

	/* connect at TCP level */
	if (proxy != NULL)
		fd = connect_to(bind_to, proxy, proxy_port);
	else
		fd = connect_to(bind_to, host, host_port);

	if (fd == -1)
	{
		dolog(LOG_ERR, "httptime: Failed to connect to %s:%d", proxy?proxy:host, proxy?proxy_port:host_port);
		return -1;
	}

	/* start SSL session if required */
	if (mode == HTTPS)
	{
		if (connect_ssl(fd, ctx, &ssl_h, &s_bio) == -1)
		{
			close(fd);
			dolog(LOG_ERR, "httptime: Failed to start SSL session");
			return -1;
		}
	}

	/* transmit HTTP request */
	if (mode == HTTPS)
		rc = WRITE_SSL(ssl_h, get_request, get_request_len);
	else
		rc = WRITE(fd, get_request, get_request_len);

	if (rc > 0)
	{
		char recv_buffer[32768 + 1] = { 0 };
		char crlfcrlf_recv = 0;

		*ts_start_recv = get_ts();

		do
		{
			int read_rc;
			int max_recv_size = sizeof(recv_buffer) - (1 + recv_buffer_in);

			if (wait_for_socket(fd, timeout) == -1)
			{
				dolog(LOG_DEBUG, "httptime: timeout");
				recv_buffer_in = 0;
				break;
			}

			if (mode == HTTPS)
				read_rc = READ_SSL(ssl_h, &recv_buffer[recv_buffer_in], max_recv_size);
			else
			{
				read_rc = read(fd, &recv_buffer[recv_buffer_in], max_recv_size);
				if (read_rc == -1)
				{
					if (errno == EINTR || errno == EAGAIN)
						continue;
				}
			}

			if (read_rc == -1)
			{
				dolog(LOG_ERR, "httptime: error reading from socket");
				recv_buffer[0] = 0x00;
				break;
			}

			recv_buffer_in += read_rc;
			recv_buffer[recv_buffer_in] = 0x00;
			crlfcrlf_recv = strstr(recv_buffer, "\r\n\r\n") != NULL;

			if (read_rc == 0)
				break;
		}
		while(!crlfcrlf_recv && recv_buffer_in < (sizeof(recv_buffer) - 1));

		if (crlfcrlf_recv)
		{
			char *date_str;

			date_str = strstr(recv_buffer, "Date:");

			if (date_str)
			{
				char *cr = strchr(date_str, '\r'), *lf = strchr(date_str, '\n');

				if (cr)
					*cr = 0x00;
				else if (lf)
					*lf = 0x00;

				date_str += 5; /* skip 'Date:' */
				while(*date_str == ' ') date_str++;

				if (date_to_time_t(date_str, ts) == -1)
				{
					dolog(LOG_INFO, "httptime: failed to convert date string '%s'", date_str);
				}
				else
				{
					global_rc = 0;
				}
			}
			else
			{
				dolog(LOG_INFO, "httptime: 'Date:'-string missing from http reply headers");
			}
		}
		else
		{
			dolog(LOG_ERR, "httptime: oversized reply headers retrieved (>= %d bytes)", sizeof(recv_buffer));
		}
	}
	else
	{
		dolog(LOG_ERR, "httptime: failed to transmit request");
	}

	/* done */
	if (mode == HTTPS)
	{
		if (close_ssl_connection(ssl_h, fd) == -1)
		{
			dolog(LOG_ERR, "httptime: failed to shutdown SSL session");
		}
	}

	close(fd);

	return global_rc;
}
