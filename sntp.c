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

int sntp(char *bind_to, char *host, int host_port, double timeout, double *ts_start_recv, double *ts)
{
	struct sockaddr_in dest;
	struct timeval send_ts;
	struct sntp_datagram packet_out, packet_in;
	int fd = udp_socket(bind_to);
	if (fd == -1)
	{
		dolog(LOG_ERR, "sntp: Failed creating socket\n");
		return -1;
	}

	/* resolve address to send to (SNTP server) */
	memset(&dest, 0x00, sizeof(dest));
	if (resolve_host(host, &dest) == -1)
		error_exit("sntp: Error resolving '%s'\n", host);
	dest.sin_family=AF_INET;
	dest.sin_port=htons(host_port);

	/* create SNTP packet */
	memset(&packet_out, 0x00, sizeof(packet_out));
	packet_out.vn      = 4;
	packet_out.mode    = 3;
	packet_out.stratum = 14;
	packet_out.poll    = 2;
	*ts_start_recv = get_ts();
	if (gettimeofday(&send_ts, NULL) == -1)
		error_exit("sntp: gettimeofday() failed");
	packet_out.originate_timestamp_secs = htonl(send_ts.tv_sec + NTP_EPOCH);
	packet_out.originate_timestamp_fraq = send_ts.tv_usec * 4295;

	/* transmit SNTP packet */
	if (sendto(fd, &packet_out, sizeof(packet_out), 0, (struct sockaddr *)&dest, sizeof(dest)) != sizeof(packet_out))
	{
		dolog(LOG_ERR, "sntp: failed transmitting SNTP packet");
		close(fd);
		return -1;
	}

	/* wait for reply */
	if (wait_for_socket(fd, timeout) == -1)
	{
		dolog(LOG_ERR, "sntp: timeout waiting for reply from NTP server %s", host);
		close(fd);
		return -1;
	}

	if (recvfrom(fd, &packet_in, sizeof(packet_in), 0, NULL, NULL) != sizeof(packet_in))
	{
		dolog(LOG_ERR, "sntp: received probably garbage");
		close(fd);
		return -1;
	}
	else
	{
		*ts = (double)(ntohl(packet_in.transmit_timestamp_secs) - NTP_EPOCH) +
		      (((double)ntohl(packet_in.transmit_timestamp_fraq)) / (4295.0 * 1000000.0));
	}

	close(fd);

	return 0;
}
