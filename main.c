#define _BSD_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>
#include <locale.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <pwd.h>
#include <math.h>
#include <sys/time.h>
#include <time.h>

#include "gen.h"
#include "error.h"
#include "log.h"
#include "utils.h"
#include "utils2.h"
#include "time.h"
#include "daytime.h"
#include "mssl.h"
#include "http.h"
#include "snts.h"
#include "irc.h"
#include "icmp.h"
#include "snmp.h"
#include "simpleptp.h"
#include "socks5sntp.h"
#include "ntpd.h"
#include "sntp.h"

#define TIME_TIME	1
#define TIME_DAYTIME	2
#define TIME_HTTP	3
#define TIME_SNTS	4
#define TIME_IRC	5
#define TIME_ICMP	6
#define TIME_SNMP	7
#define TIME_SIMPLEPTP1	8
#define TIME_SOCKS5SNTP	9
#define TIME_SNTP	10

#define DEFAULT_SLEEP_INTERVAL	60
#define DEFAULT_MAX_OFFSET	7200.0
#define DEFAULT_FUDGE_FACTOR	0.0
#define DEFAULT_SNTS_GROUP	1

int verbose = 0;

int do_measure(int mode, char *host, int host_port, int ip_mode, double timeout, char *proxy, int proxy_port, char *interface_addr, int http_mode, SSL_CTX *ctx, int snts_group, char *auth_user, char *auth_pw, int sleep_interval, char *community, double *ts_start_recv, double *ts_measurement)
{
	int rc = -1;

	if (mode == TIME_TIME)
	{
		rc = gtime(interface_addr, host, host_port, timeout, ip_mode, ts_start_recv, ts_measurement);
	}
	else if (mode == TIME_DAYTIME)
	{
		rc = daytime(interface_addr, host, host_port, timeout, ip_mode, ts_start_recv, ts_measurement);
	}
	else if (mode == TIME_HTTP)
	{
		rc = httptime(interface_addr, host, host_port, timeout, proxy, proxy_port, http_mode, ctx, ts_start_recv, ts_measurement);
	}
	else if (mode == TIME_SNTS)
	{
		rc = snts(interface_addr, snts_group, host, ts_start_recv, ts_measurement);
	}
	else if (mode == TIME_IRC)
	{
		rc = irc(interface_addr, host, host_port, auth_user, auth_pw, sleep_interval, ts_start_recv, ts_measurement);
	}
	else if (mode == TIME_ICMP)
	{
		rc = icmp(interface_addr, host, timeout, ts_start_recv, ts_measurement);
	}
	else if (mode == TIME_SNMP)
	{
		rc = snmp(host, host_port, community, ts_start_recv, ts_measurement);
	}
	else if (mode == TIME_SIMPLEPTP1)
	{
		rc = simple_ptp(host_port, interface_addr, host, timeout, ts_start_recv, ts_measurement);
	}
	else if (mode == TIME_SOCKS5SNTP)
	{
		rc = socks5sntp(interface_addr, host, host_port, timeout, proxy, proxy_port, auth_user, auth_pw, ts_start_recv, ts_measurement);
	}
	else if (mode == TIME_SNTP)
	{
		rc = sntp(interface_addr, host, host_port, timeout, ts_start_recv, ts_measurement);
	}
	else
		error_exit("unknown mode %d", mode);

	return rc;
}

void store_statistics(char *stats_file, double ts, double offset, double recv_duration)
{
	FILE *fh = fopen(stats_file, "a+");
	if (!fh)
		error_exit("Error opening statistics file %s.", stats_file);

	fprintf(fh, "%.8f %.8f %.8f\n", ts, offset, recv_duration);

	fclose(fh);
}

void version(void)
{
	printf("OmniSync v" VERSION ", (C) 2007-2008 by folkert@vanheusden.com\n\n");
}

void help(void)
{
	version();

	printf("-M x   mode:\n");
	printf("       time/tcp time/udp\n");
	printf("       daytime/tcp daytime/udp\n");
	printf("       http/https\n");
	printf("       snts\n");
	printf("       irc\n");
	printf("       icmp\n");
	printf("       snmp\n");
	printf("       simpleptp1\n");
	printf("       socks5sntp\n");
	printf("       sntp\n");
	printf("-G x   snts group (default 1)\n");
	printf("-F x   fudge factor (default: %f)\n", DEFAULT_FUDGE_FACTOR);
	printf("-m x   max. offset (default: %f)\n", DEFAULT_MAX_OFFSET);
	printf("-p x   proxy-server (http/https/socks5sntp only)\n");
	printf("-B x   bind to interface x (not for snmp)\n");
	printf("-I x   username[:password] (irc/socks5 auth. only)\n");
	printf("-c x   community (snmp only)\n");
	printf("-h x   host to connect to\n");
	printf("-u x   ntpd shared memory unit\n");
	printf("-z x   do an initial step, to speed up syncing, parameter is number of samples");
	printf("-S x   write measurements to file x\n");
	printf("-n     do NOT submit to NTPd/set clock, query only (use in combination with -v and -f)\n");
	printf("-f     do not fork\n");
	printf("-i x   check interval (default: %d)\n", DEFAULT_SLEEP_INTERVAL);
	printf("-d x   timeout\n");
	printf("-U x   set user to run as\n");
	printf("-P x   write pid to file x\n");
	printf("-v     increase verbosity\n");
	printf("-V     show version & exit\n");
	printf("--help this help\n");
}

int main(int argc, char *argv[])
{
	SSL_CTX *ctx = initialize_ctx();
	int mode = -1, ip_mode = -1, http_mode = -1;
	char *host = NULL, *proxy = NULL;
	int host_port = -1, proxy_port = -1;
	struct shmTime * pst = NULL;
	int unit_nr = 0;
	double fudge_factor = DEFAULT_FUDGE_FACTOR;
	double max_offset = DEFAULT_MAX_OFFSET;
	int sleep_interval = -1;
	int c;
	char do_fork = 1;
	char *dummy = NULL;
	char set_clock = 1;
	int uid = -1, gid = -1;
	char *pidfile = NULL;
	char *stats_file = NULL;
	int snts_group = DEFAULT_SNTS_GROUP;
	char *auth_user_pw = NULL;
	int precision = 0;	/* 0 = precision of 1 sec., -1 = 0.5s */
	int n_initial_measurements = 0;
	char *community = "public";
	double timeout = 5.0;
	char *interface_addr = strdup("0.0.0.0:0");
	char *auth_pw = NULL, *auth_user = NULL;
	char *colon;

	srand((int)get_ts() ^ (int)(get_ts() * 1000000.0));

	while((c = getopt(argc, argv, "B:d:c:z:I:G:S:P:U:nF:m:M:p:h:u:i:fvVh")) != -1)
	{
		switch(c)
		{
			case 'B':
				interface_addr = optarg;
				break;

			case 'd':
				timeout = atof(optarg);
				if (timeout < 0)
					error_exit("'-d' requires a positive value");
				break;

			case 'c':
				community = optarg;
				break;

			case 'z':
				n_initial_measurements = atoi(optarg);
				if (n_initial_measurements < 0)
					error_exit("'-z' requires a positive value");
				break;

			case 'I':
				auth_user_pw = mystrdup(optarg);
				break;

			case 'G':
				snts_group = atoi(optarg);
				if (snts_group < 0)
					error_exit("'-G' requires a positive value");
				break;

			case 'P':
				pidfile = optarg;
				break;

			case 'U':
				{
					struct passwd *pw = getpwnam(optarg);
					if (pw == NULL)
						error_exit("User '%s' is not known", optarg);
					uid = pw -> pw_uid;
					gid = pw -> pw_gid;
				}
				break;

			case 'n':
				set_clock = 0;
				break;

			case 'F':
				fudge_factor = atof(optarg);
				break;

			case 'm':
				max_offset = atof(optarg);
				break;

			case 'i':
				sleep_interval = atoi(optarg);
				if (sleep_interval < 0)
					error_exit("sleep interval (-i) must be > 0");
				if (sleep_interval < 60)
					fprintf(stderr, "WARNING: sleep interval set to < 60, please note that ntpd doesn't poll more often then once every 64 seconds! (unless configured different)");
				break;

			case 'M':
				if (strcasecmp(optarg, "time/tcp") == 0)
				{
					mode = TIME_TIME;
					ip_mode = IP_TCP;
				}
				else if (strcasecmp(optarg, "time/udp") == 0)
				{
					mode = TIME_TIME;
					ip_mode = IP_UDP;
				}
				else if (strcasecmp(optarg, "daytime/tcp") == 0)
				{
					mode = TIME_DAYTIME;
					ip_mode = IP_TCP;
				}
				else if (strcasecmp(optarg, "daytime/udp") == 0)
				{
					mode = TIME_DAYTIME;
					ip_mode = IP_UDP;
				}
				else if (strcasecmp(optarg, "http") == 0)
				{
					mode = TIME_HTTP;
					http_mode = HTTP;
				}
				else if (strcasecmp(optarg, "https") == 0)
				{
					mode = TIME_HTTP;
					http_mode = HTTPS;
				}
				else if (strcasecmp(optarg, "snts") == 0)
				{
					mode = TIME_SNTS;
				}
				else if (strcasecmp(optarg, "irc") == 0)
				{
					mode = TIME_IRC;
				}
				else if (strcasecmp(optarg, "icmp") == 0)
				{
					mode = TIME_ICMP;
				}
				else if (strcasecmp(optarg, "snmp") == 0)
				{
					mode = TIME_SNMP;
				}
				else if (strcasecmp(optarg, "simpleptp1") == 0)
				{
					mode = TIME_SIMPLEPTP1;
				}
				else if (strcasecmp(optarg, "socks5sntp") == 0)
				{
					mode = TIME_SOCKS5SNTP;
				}
				else if (strcasecmp(optarg, "sntp") == 0)
				{
					mode = TIME_SNTP;
				}
				else
				{
					fprintf(stderr, "'%s' is not recognized\n", optarg);
					help();
					return 1;
				}
				break;

			case 'p':
				proxy_port = -1; 	/* default */
				proxy = mystrdup(optarg);
				dummy = strchr(proxy, ':');
				if (dummy)
				{
					*dummy = 0x00;
					proxy_port = atoi(dummy + 1);
				}
				break;

			case 'h':
				host = mystrdup(optarg);
				dummy = strchr(host, ':');
				if (dummy)
				{
					*dummy = 0x00;
					host_port = atoi(dummy + 1);
				}
				break;

			case 'f':
				do_fork = 0;
				break;

			case 'u':
				unit_nr = atoi(optarg);
				if (unit_nr < 0)
					error_exit("-u requires a positive value\n");
				if (unit_nr > 3)
					error_exit("NTPd normally supports only 4 shared memory devices, still continuing though\n");
				break;

			case 'v':
				verbose++;
				break;

			case 'V':
				version();
				return 0;

			default:
				help();
				return 1;
		}
	}

	if (!do_fork || verbose)
		version();

	if (mode == -1)
	{
		fprintf(stderr, "No mode given: use the '-M' flag\n");
		return 1;
	}

	if (host == NULL && mode != TIME_SNTS && mode != TIME_SIMPLEPTP1)
	{
		fprintf(stderr, "No host to connect to given, use the '-h' flag\n");
		return 1;
	}

	if ((mode == TIME_TIME || mode == TIME_DAYTIME) && proxy != NULL)
	{
		fprintf(stderr, "time/daytime does not support a proxy server\n");
		return 1;
	}
	else if (mode == TIME_HTTP && ip_mode != -1 && ip_mode != IP_TCP)
	{
		fprintf(stderr, "http(s) only works via TCP\n");
		return 1;
	}
	else if (mode == TIME_ICMP && host_port != -1)
	{
		fprintf(stderr, "One cannot set a port for ICMP queries.\n");
		return 1;
	}

	if (mode == TIME_SOCKS5SNTP && proxy == NULL)
	{
		fprintf(stderr, "socks4sntp requires the address of the socks5 proxy server\n");
		return 1;
	}

	if (mode == TIME_IRC && auth_user_pw == NULL)
	{
		fprintf(stderr, "irc mode requires a username[/password], use '-I user[:password]'\n");
		return 1;
	}

	if (proxy && proxy_port == -1)
	{
		if (mode == TIME_SOCKS5SNTP)
			proxy_port = 1080;
		else if (mode == TIME_HTTP)
			proxy_port = 8080;
	}

	if (mode == TIME_ICMP)
	{
		precision = -10;	/* 1/1024s */
	}

	if (sleep_interval == -1)
	{
		sleep_interval = DEFAULT_SLEEP_INTERVAL;
	}
	else if (mode == TIME_SNTS)
	{
		fprintf(stderr, "snts-mode is in a constant receive loop so 'sleep interval' doesn't make sense\n");
		return 1;
	}

	if (mode == TIME_SNMP && strcmp(interface_addr, "0.0.0.0:0") != 0)
	{
		fprintf(stderr, "Interface is not for snmp mode\n");
		return 1;
	}
	else if (mode == TIME_SIMPLEPTP1 && strcmp(interface_addr, "0.0.0.0:0") == 0)
	{
		fprintf(stderr, "simpleptp1 requires an interface address\n");
		return 1;
	}

	if (host_port == -1)
	{
		if (mode == TIME_TIME)
			host_port = 37;
		else if (mode == TIME_DAYTIME)
			host_port = 13;
		else if (mode == TIME_HTTP)
		{
			if (http_mode == HTTP)
				host_port = 80;
			else if (http_mode == HTTPS)
				host_port = 443;
		}
		else if (mode == TIME_SNTS)
		{
			host_port = 724;
		}
		else if (mode == TIME_IRC)
		{
			host_port = 6667;
		}
		else if (mode == TIME_SNMP)
		{
			host_port = 161;
		}
		else if (mode == TIME_SIMPLEPTP1)
		{
			host_port = 319;
		}
		else if (mode == TIME_SOCKS5SNTP || mode == TIME_SNTP)
		{
			host_port = 123;
		}
	}

	if (setlocale(LC_ALL, "C") == NULL)
		error_exit("Failed to set locale to 'C' - which is required for correct daytime-conversion.");

	if (set_clock)
	{
		pst = get_shm_pointer(unit_nr);
		if (!pst)
			error_exit("Failed to connect to NTP daemon");
	}

	if (auth_user_pw)
	{
		auth_user = mystrdup(auth_user_pw);

		colon = strchr(auth_user, ':');
		if (colon)
		{
			*colon = 0x00;
			auth_pw = colon + 1;
		}
	}

	if (verbose)
	{
		printf("mode: ");
		if (mode == TIME_TIME)
			printf("time");
		else if (mode == TIME_DAYTIME)
			printf("daytime");
		else if (mode == TIME_HTTP)
			printf("http%s", http_mode == HTTPS ? "s" : "");
		else if (mode == TIME_SNTS)
			printf("snts");
		else if (mode == TIME_IRC)
			printf("irc");
		else if (mode == TIME_ICMP)
			printf("icmp");
		else if (mode == TIME_SNMP)
			printf("snmp");
		else if (mode == TIME_SIMPLEPTP1)
			printf("simpleptp1");
		else if (mode == TIME_SOCKS5SNTP)
			printf("socks5sntp");
		else if (mode == TIME_SNTP)
			printf("sntp");

		if (mode != TIME_HTTP)
		{
			if (ip_mode == IP_TCP)
				printf(" TCP");
			else if (ip_mode == IP_UDP)
				printf(" UDP");
		}
		printf("\n");

		if (mode == TIME_SNTS || mode == TIME_SIMPLEPTP1)
			printf("Listening on port %d (UDP)\n", host_port);
		else
			printf("Connect to: %s:%d\n", host, host_port);
		if ((mode == TIME_HTTP || mode == TIME_SOCKS5SNTP) && proxy != NULL)
			printf("Proxy: %s:%d\n", proxy, proxy_port);
		else if (mode == TIME_SNTS)
			printf("Group: %d\n", snts_group);
		else if (mode == TIME_SNMP)
			printf("Community: %s\n", community);

		printf("Check interval: %d\n", sleep_interval);

		printf("NTPd unit: %d\n", unit_nr);

		printf("Fudge factor: %f\n", fudge_factor);

		if (!set_clock)
			printf("NOT submitting measurement to NTPd\n");
	}

	if (gid != -1)
	{
		if (setgid(gid) == -1)
			error_exit("Failed to set group to %d", gid);
	}

	if (uid != -1)
	{
		if (setuid(uid) == -1)
			error_exit("Failed to set user to %d", uid);
	}

	if (do_fork)
	{
#ifndef IRIX
		if (daemon(-1, -1) == -1)
			error_exit("Failed to become daemon process");
#endif

		if (pidfile)
			write_pidfile(pidfile);
	}

	if (n_initial_measurements)
	{
		struct timeval tv;
		double total_offset = 0.0;
		double ts_start_recv, ts_measurement;
		int loop;

		for(loop=0; loop<n_initial_measurements; loop++)
		{
			int rc;

			if (verbose)
				printf("Initial stepping, measuring %d   \n", n_initial_measurements - loop);

			do
			{
				rc = do_measure(mode, host, host_port, ip_mode, timeout, proxy, proxy_port, interface_addr, http_mode, ctx, snts_group, auth_user, auth_pw, sleep_interval, community, &ts_start_recv, &ts_measurement);

				if (rc == -1)
					dolog(LOG_ERR, "Not using measurement");

				if (mode != TIME_SNTS && mode != TIME_IRC)
					mysleep(sleep_interval);
			}
			while(rc == -1);

			total_offset += ts_measurement - ts_start_recv;
		}

		total_offset /= (double)n_initial_measurements;

		if (verbose)
			printf("Initial stepping, compensating average offset: %f\n", total_offset);

		if (set_clock)
		{
			total_offset += get_ts();

			tv.tv_sec = total_offset;
			tv.tv_usec = (int)(((double)total_offset - tv.tv_sec) * 1000000.0);

			if (settimeofday(&tv , NULL))
				error_exit("settimeofday failed");
		}
	}

	for(;;)
	{
		int rc = -1;
		double ts_start_recv, ts_measurement, offset;
		double recv_start, recv_end, recv_duration;
		static double offset_stddev = 0.0, total_offset = 0.0;
		static int n_msgs = 0, n_not_acknowledgded = 0;

		recv_start = get_ts();
		rc = do_measure(mode, host, host_port, ip_mode, timeout, proxy, proxy_port, interface_addr, http_mode, ctx, snts_group, auth_user, auth_pw, sleep_interval, community, &ts_start_recv, &ts_measurement);
		recv_end = get_ts();

		recv_duration = recv_end - recv_start;

		if (mode == TIME_IRC && recv_duration >= sleep_interval)
			recv_duration -= sleep_interval;

		offset = ts_measurement - ts_start_recv;

		if (rc == 0 && verbose)
		{
			n_msgs++;
			printf("Msg %d measured %f at %f (offset: %f), took %f seconds to measure.\n", n_msgs, ts_measurement, ts_start_recv, offset, recv_duration);
		}

		if (rc == 0 && fabs(offset) < max_offset && set_clock)
		{
			if (submit_to_ntpd(pst, ts_start_recv, ts_measurement, fudge_factor, precision))
			{
				n_not_acknowledgded++;
				if (verbose)
					printf("Previous timestamp was NOT retrieved by NTP daemon (total not retrieved: %d).\n", n_not_acknowledgded);
			}

			if (stats_file)
				store_statistics(stats_file, ts_start_recv, offset, recv_duration);
		}
		else
		{
			dolog(LOG_INFO, "Not submitting measurement to NTP daemon.");
		}

		if (rc == 0 && verbose)
		{
			offset_stddev += pow(offset, 2.0);
			total_offset += offset;

			printf("Average offset: %f, std.dev.: %f\n", total_offset / (double)n_msgs, sqrt((offset_stddev / (double)n_msgs) - pow(total_offset / (double)n_msgs, 2.0)));
		}

		if (mode != TIME_SNTS && mode != TIME_IRC)
		{
			mysleep(sleep_interval);
		}
	}

	return 0;
}
