#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include "gen.h"
#include "error.h"
#include "ntpd.h"

#define NTP_KEY 1314148400

struct shmTime * get_shm_pointer(int unitNr)
{
	void *addr;
	struct shmTime *pst;
	int shmid = shmget(NTP_KEY + unitNr, sizeof(struct shmTime), IPC_CREAT);
	if (shmid == -1)
		error_exit("get_shm_pointer: shmget failed");

	addr = shmat(shmid, NULL, 0);
	if (addr == (void *)-1)
		error_exit("get_shm_pointer: shmat failed");

	pst = (struct shmTime *)addr;

	memset(pst, 0x00, sizeof(struct shmTime));

	return pst;
}

int submit_to_ntpd(struct shmTime *pst, double ts_start_recv, double ts_measurement, double fudge_factor, int precision)
{
	double final_ts = ts_measurement + fudge_factor;
	int pvalid = pst -> valid;

	pst -> valid = 0; /* in case we get a context switch while setting this structure */
	pst -> clockTimeStampSec    = (time_t)final_ts;
	pst -> clockTimeStampUSec   = (int)((final_ts - (double)pst -> clockTimeStampSec) * 1000000.0);
	pst -> receiveTimeStampSec  = (time_t)ts_start_recv;
	pst -> receiveTimeStampUSec = (int)((ts_start_recv - (double)pst -> receiveTimeStampSec) * 1000000.0);
	pst -> leap  =
	pst -> mode  =
	pst -> count = 0;
	pst -> precision = precision;
	pst -> valid = 1;

	return pvalid;
}
