#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <fcntl.h>

#include "compiler.h"
#include "types.h"
#include "log.h"

static unsigned int current_loglevel = DEFAULT_LOGLEVEL;
static char logbuf[PAGE_SIZE];

void loglevel_set(unsigned int loglevel)
{
	current_loglevel = loglevel;
}

unsigned int loglevel_get(void)
{
	return current_loglevel;
}

bool wont_print(unsigned int loglevel)
{
	return loglevel != LOG_MSG && loglevel > loglevel_get();
}

static void __print_on_level(unsigned int loglevel, const char *format, va_list params)
{
	size_t size;

	size = vsnprintf(logbuf, PAGE_SIZE, format, params);
	write(STDOUT_FILENO, logbuf, size);
}

void print_on_level(unsigned int loglevel, const char *format, ...)
{
	va_list params;

	if (wont_print(loglevel))
		return;

	va_start(params, format);
	__print_on_level(loglevel, format, params);
	va_end(params);
}
