#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <signal.h>
#include <syslog.h>

#include "gen.h"

void dolog(int priority, char *format, ...)
{
	char buffer[4096];
	va_list ap;

	va_start(ap, format);
	vsnprintf(buffer, sizeof(buffer), format, ap);
	va_end(ap);

	if (verbose > 0)
		fprintf(stderr, "%d] %s (%d / %s)\n", priority, buffer, errno, strerror(errno));

	syslog(priority, "%s (%m)", buffer);
}
