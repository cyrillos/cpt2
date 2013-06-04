#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>

#include <sys/types.h>

#include <getopt.h>

#include "compiler.h"
#include "convert.h"
#include "cpt2.h"
#include "log.h"
#include "net.h"

#include "res/vdso-rhel.h"

opts_t global_opts;

int main(int argc, char *argv[])
{
	unsigned int loglevel = DEFAULT_LOGLEVEL;
	int opt, idx;

	const char short_opts[] = "f:D:r:v";
	static struct option long_opts[] = {
		{ "dumpfile",		required_argument, 0, 'f' },
		{ "root",		required_argument, 0, 'r' },
		{ "images-dir",		required_argument, 0, 'D' },
		{ },
	};

	while (1) {
		opt = getopt_long(argc, argv, short_opts, long_opts, &idx);
		if (opt == -1)
			break;

		switch (opt) {
		case 'f':
			global_opts.cpt_filename = optarg;
			break;
		case 'D':
			global_opts.criu_dirname = optarg;
			break;
		case 'r':
			global_opts.root_dirname = optarg;
			break;
		case 'v':
			if (optind < argc) {
				char *opt = argv[optind];

				if (isdigit(*opt)) {
					loglevel = atoi(opt);
					optind++;
				} else
					loglevel++;
			} else
				loglevel++;
		default:
			break;
		}
	}

	loglevel_set(max(loglevel, (unsigned int)DEFAULT_LOGLEVEL));

	if (!global_opts.cpt_filename)
		goto usage;

	if (!global_opts.root_dirname)
		goto usage;

	if (!global_opts.criu_dirname)
		global_opts.criu_dirname = ".";

	return convert();

usage:
	pr_msg("\nUsage:\n");
	pr_msg("  %s -f <dumpfile> -r <root> [-D <dir>]\n", argv[0]);
	return -1;
}
