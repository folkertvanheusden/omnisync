#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <time.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "gen.h"
#include "error.h"
#include "utils.h"
#include "utils2.h"
#include "log.h"

#define NTP_EPOCH            (86400U * (365U * 70U + 17U))
#define NTP_PORT             123

struct sntp_datagram
{
	unsigned char mode : 3;
	unsigned char vn : 3;
	unsigned char li : 2;
	unsigned char stratum;
	char poll;
	char precision;
	u_int32_t root_delay;
	u_int32_t root_dispersion;
	u_int32_t reference_identifier;
	u_int32_t reference_timestamp_secs;
	u_int32_t reference_timestamp_fraq;
	u_int32_t originate_timestamp_secs;
	u_int32_t originate_timestamp_fraq;
	u_int32_t receive_timestamp_seqs;
	u_int32_t receive_timestamp_fraq;
	u_int32_t transmit_timestamp_secs;
	u_int32_t transmit_timestamp_fraq;
};

int socks5sntp(char *bind_to, char *host, int host_port, double timeout, char *socks5_host, int socks5_port, char *socks5_username, char *socks5_password, double *ts_start_recv, double *ts)
{
	int xmit_fd;
	struct sockaddr_in dest, socks_dest;
	struct timeval send_ts;
	struct sntp_datagram packet_out, packet_in;
	unsigned char io_buffer[256], dummy_buffer[128];
	int io_len;
	int fd = connect_to(bind_to, socks5_host, socks5_port);
	if (fd == -1)
	{
		dolog(LOG_ERR, "socks5sntp: Failed to connect to %s:%d", socks5_host, socks5_port);
		return -1;
	}

	/* inform socks server about the auth. methods we support */
	if (socks5_username != NULL)
	{
		io_buffer[0] = 0x05;	/* version */
		io_buffer[1] = 2;	/* 2 authentication methods */
		io_buffer[2] = 0x00;	/* method 1: no authentication */
		io_buffer[3] = 0x02;	/* method 2: username/password */
		io_len = 4;
	}
	else
	{
		io_buffer[0] = 0x05;	/* version */
		io_buffer[1] = 1;	/* 2 authentication methods */
		io_buffer[2] = 0x00;	/* method 1: no authentication */
		io_len = 3;
	}
	if (WRITE(fd, io_buffer, io_len) == -1)
	{
		dolog(LOG_ERR, "socks5sntp: failed transmitting authentication methods to socks5 server");
		close(fd);
		return -1;
	}

	/* wait for reply telling selected authentication method */
	if (READ(fd, io_buffer, 2) == -1)
	{
		dolog(LOG_ERR, "socks5ntp: socks5 server does not reply with selected auth. mode");
		close(fd);
		return -1;
	}

	if (io_buffer[0] != 0x05)
		error_exit("socks5sntp: reply with requested authentication method does not say version 5 (%02x)", io_buffer[0]);

	if (io_buffer[1] == 0x00)
	{
		dolog(LOG_DEBUG, "socks5sntp: \"no authentication at all\" selected by server");
	}
	else if (io_buffer[1] == 0x02)
	{
		dolog(LOG_DEBUG, "socks5sntp: selected username/password authentication");
	}
	else
		error_exit("socks5sntp: socks5 refuses our authentication methods");

	/* in case the socks5 server asks us to authenticate, do so */
	if (io_buffer[1] == 0x02)
	{
		int io_len;

		if (socks5_username == NULL || socks5_password == NULL)
			error_exit("socks5sntp: socks5 server requests username/password authentication");

		io_buffer[0] = 0x01;	/* version */
		io_len = snprintf(&io_buffer[1], sizeof(io_buffer) - 1, "%c%s%c%s", (int)strlen(socks5_username), socks5_username, (int)strlen(socks5_password), socks5_password);

		if (WRITE(fd, io_buffer, io_len + 1) == -1)
		{
			dolog(LOG_ERR, "socks5sntp: failed transmitting username/password to socks5 server");
			close(fd);
			return -1;
		}

		if (READ(fd, io_buffer, 2) == -1)
		{
			dolog(LOG_ERR, "socks5sntp: failed receiving authentication reply");
			close(fd);
			return -1;
		}

		if (io_buffer[1] != 0x00)
			error_exit("socks5sntp: password authentication failed");
	}

	/* ask socks5 server to associate with sntp server */
	io_buffer[0] = 0x05;	/* version */
	io_buffer[1] = 0x03;	/* UDP associate */
	io_buffer[2] = 0x00;	/* reserved */
	io_buffer[3] = 0x01;	/* ipv4 */
	io_buffer[4] = 0;
	io_buffer[5] = 0;
	io_buffer[6] = 0;
	io_buffer[7] = 0;
	io_buffer[8] = 0;
	io_buffer[9] = 0;
	if (WRITE(fd, io_buffer, 10) == -1)
	{
		dolog(LOG_ERR, "socks5sntp: failed to transmit associate request");
		close(fd);
		return -1;
	}

	if (READ(fd, io_buffer, 10) == -1)
	{
		dolog(LOG_ERR, "socks5sntp: command reply receive failure");
		close(fd);
		return -1;
	}

	/* generate address structure containing relay address of socks5 udp "connection" */
	memset(&socks_dest, 0x00, sizeof(socks_dest));
	socks_dest.sin_family=AF_INET;
	socks_dest.sin_port=htons(io_buffer[8] * 256 + io_buffer[9]);
	snprintf(dummy_buffer, sizeof(dummy_buffer), "%d.%d.%d.%d", io_buffer[4], io_buffer[5], io_buffer[6], io_buffer[7]);
	socks_dest.sin_addr.s_addr= inet_addr(dummy_buffer);
	/* connect to relay */
	xmit_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (xmit_fd == -1)
		error_exit("socks5sntp: failed to create socket");
	if (connect(xmit_fd, (struct sockaddr *)&socks_dest, sizeof(socks_dest)) == -1)
		error_exit("socks5sntp: error \"connecting\" to socks relay host");

	/* verify reply */
	if (io_buffer[0] != 0x05)
		error_exit("socks5sntp: bind request replies with version other than 0x05 (%02x)", io_buffer[0]);

	if (io_buffer[1] != 0x00)
		error_exit("socks5sntp: failed to bind (%02x)", io_buffer[1]);

	if (io_buffer[3] != 0x01)
		error_exit("socks5sntp: only accepting bind-replies with IPv4 address (%02x)", io_buffer[3]);

	/* resolve real address to send to (SNTP server) */
	memset(&dest, 0x00, sizeof(dest));
	if (resolve_host(host, &dest) == -1)
		error_exit("socks5sntp: failed to resolve hostname '%s'", host);

	/* create SNTP packet */
	memset(&packet_out, 0x00, sizeof(packet_out));
	packet_out.vn      = 4;
	packet_out.mode    = 3;
	packet_out.stratum = 14;
	packet_out.poll    = 2;
	*ts_start_recv = get_ts();
	if (gettimeofday(&send_ts, NULL) == -1)
		error_exit("socks5sntp: gettimeofday() failed");
	packet_out.originate_timestamp_secs = htonl(send_ts.tv_sec + NTP_EPOCH);
	packet_out.originate_timestamp_fraq = send_ts.tv_usec * 4295;
	/* encapsulate SNTP packet in packet for UDP socks relay */
	io_buffer[0] = 0x00;	/* RSV */
	io_buffer[1] = 0x00;
	io_buffer[2] = 0;	/* FRAG */
	io_buffer[3] = 0x01;	/* IPv4 */
	io_buffer[4] = (dest.sin_addr.s_addr      ) & 255;
	io_buffer[5] = (dest.sin_addr.s_addr >>  8) & 255;
	io_buffer[6] = (dest.sin_addr.s_addr >> 16) & 255;
	io_buffer[7] = (dest.sin_addr.s_addr >> 24) & 255;
	io_buffer[8] = (host_port >> 8) & 255;
	io_buffer[9] = (host_port     ) & 255;
	memcpy(&io_buffer[10], &packet_out, sizeof(packet_out));
	io_len = 10 + sizeof(packet_out);

	/* transmit (encapsulated) SNTP packet! */
	if (send(xmit_fd, io_buffer, io_len, 0) != io_len)
	{
		dolog(LOG_ERR, "socks5sntp: failed transmitting SNTP packet");
		close(xmit_fd);
		close(fd);
		return -1;
	}

	/* wait for reply */
	if (wait_for_socket(xmit_fd, timeout) == -1)
	{
		dolog(LOG_ERR, "socks5sntp: timeout waiting for reply from NTP server %s", host);
		close(xmit_fd);
		close(fd);
		return -1;
	}

	if (recvfrom(xmit_fd, io_buffer, io_len, 0, NULL, NULL) != io_len)
	{
		dolog(LOG_ERR, "socks5sntp: received probably garbage");
		close(xmit_fd);
		close(fd);
		return -1;
	}
	else
	{
		memcpy(&packet_in, &io_buffer[10], sizeof(packet_in));

		*ts = (double)(ntohl(packet_in.transmit_timestamp_secs) - NTP_EPOCH) +
		      (((double)ntohl(packet_in.transmit_timestamp_fraq)) / (4295.0 * 1000000.0));
	}

	close(xmit_fd);
	close(fd);

	return 0;
}
