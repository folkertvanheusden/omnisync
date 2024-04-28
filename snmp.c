/* based on http://www.usenet-forums.com/snmp-users/290926-win32-simple-net-snmp-c-program-fails-execution.html */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <math.h>
#include <stdlib.h>
#include <time.h>

#include "gen.h"
#include "error.h"
#include "utils2.h"
#include "log.h"

int snmp_timestr_to_time_t(char *in, double *ts_measurement)
{
	/* STRING: 2008-1-23,20:27:21.0,+1:0 */
	struct tm stm;
	double sec, frac;
	char *dummy;
	double dummyval;

	if (str_to_val(&in[8], &dummyval) == -1)
		return -1;
	stm.tm_year = dummyval - 1900;
	if (str_to_val(&in[13], &dummyval) == -1)
		return -1;
	stm.tm_mon  = dummyval - 1;

	dummy = strchr(&in[13], '-');
	if (!dummy)
		return -1;
	dummy++;
	if (str_to_val(dummy, &dummyval) == -1)
		return -1;
	stm.tm_mday = dummyval;

	dummy = strchr(dummy, ',');
	if (!dummy)
		return -1;
	dummy++;
	if (str_to_val(dummy, &dummyval) == -1)
		return -1;
	stm.tm_hour = dummyval;

	if (str_to_val(dummy + 3, &dummyval) == -1)
		return -1;
	stm.tm_min = dummyval;
	if (str_to_val(dummy + 6, &sec) == -1)
		return -1;

	frac = sec - floor(sec);
	stm.tm_sec = (int)floor(sec);

	*ts_measurement = (double)mktime(&stm) + frac;

	return 0;
}

int snmp(char *host, int host_port, char *community, double *ts_start_recv, double *ts_measurement)
{
	int rc = -1;
	struct snmp_session session, *psession;
	struct snmp_pdu *request;
	struct snmp_pdu *response;
	int peername_len = strlen(host) + 1 + 5 + 1;
	char * peername = mymalloc(peername_len);
	oid anOID[MAX_OID_LEN];
	size_t anOID_len = MAX_OID_LEN;
	int status;

	init_snmp("OmniSync");

	snmp_sess_init(&session);

	snprintf(peername, peername_len, "%s:%d", host, host_port);
	session.peername      = peername;
	session.version       = SNMP_VERSION_1;
	session.community     = community;
	session.community_len = strlen(session.community);

	SOCK_STARTUP;
	if ((psession = snmp_open(&session)) == NULL)
		error_exit("snmp: failed to start session");

	/* Create PDU and add OID */
	request = snmp_pdu_create(SNMP_MSG_GET);
	read_objid(".1.3.6.1.2.1.25.1.2.0", anOID, &anOID_len);
	snmp_add_null_var(request, anOID, anOID_len);

	/* Send the request */
	*ts_start_recv = get_ts();
	status = snmp_synch_response(psession, request, &response);

	if (status != STAT_SUCCESS)
	{
		dolog(LOG_ERR, "snmp: snmp_synch_response failed; %s", snmp_errstring(status));
	}
	else if (status == STAT_SUCCESS && response -> errstat != SNMP_ERR_NOERROR)
	{
		dolog(LOG_ERR, "snmp: %s => %s", session.peername, snmp_errstring(response -> errstat));
	}
	else if (status == STAT_SUCCESS)
	{
		struct variable_list *current_variable = response -> variables;
		char buffer[128];

		if (current_variable -> next_variable != NULL)
			error_exit("snmp: expected only 1 value in respons from server");

		if (snprint_value(buffer, sizeof(buffer), current_variable -> name, current_variable -> name_length, current_variable) == -1)
			error_exit("snmp: error converting data, buffer too small");

		if (snmp_timestr_to_time_t(buffer, ts_measurement) == -1)
			error_exit("snmp: returned date-string ('%s') not understood", buffer);

		rc = 0;
	}
	else
	{
		error_exit("snmp: unexpected situation");
	}

	if (response)
		snmp_free_pdu(response);

	snmp_close(psession);

	free(peername);

	SOCK_CLEANUP;

	return rc;
}
