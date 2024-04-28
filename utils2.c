#include <stdlib.h>
#include <sys/time.h>
#include <time.h>

#include "error.h"

int str_to_val(char *in, double *val)
{
	char *endptr = NULL;

	*val = strtod(in, &endptr);
	if (*val == 0 && endptr == in)
		return -1;

	return 0;
}

double get_ts(void)
{
	struct timeval ts;

	if (gettimeofday(&ts, NULL) == -1)
		error_exit("get_ts: gettimeofday failed");

	return (((double)ts.tv_sec) + ((double)ts.tv_usec)/1000000.0);
}

char *mymalloc(int n)
{
	char *p = (char *)malloc(n);
	if (!p)
		error_exit("failed to allocate %d bytes of memory", n);

	return p;
}
