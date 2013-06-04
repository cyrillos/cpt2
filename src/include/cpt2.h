#ifndef __CPT2_H__
#define __CPT2_H__

/*
 * Please gather all global variables in this file only.
 */

typedef struct {
	char		*cpt_filename;
	char		*criu_dirname;
	char		*root_dirname;
} opts_t;

extern opts_t global_opts;

#endif /* __CPT2_H__ */
