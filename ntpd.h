struct shmTime {
	int    mode; /* 0 - if valid set
		      *       use values,
		      *       clear valid
		      * 1 - if valid set
		      *       if count before and after read of
		      *       values is equal,
		      *         use values
		      *       clear valid
		      */
	int    count;
	time_t clockTimeStampSec;      /* external clock */
	int    clockTimeStampUSec;     /* external clock */
	time_t receiveTimeStampSec;    /* internal clock, when external value was received */
	int    receiveTimeStampUSec;   /* internal clock, when external value was received */
	int    leap;
	int    precision;
	int    nsamples;
	int    valid;
	int    dummy[10];
};

struct shmTime * get_shm_pointer(int unitNr);
int submit_to_ntpd(struct shmTime *pst, double ts_start_recv, double ts_measurement, double fudge_factor, int precision);
