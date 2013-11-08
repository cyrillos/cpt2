#ifndef __CPT2_STRING_H__
#define __CPT2_STRING_H__

#include <sys/types.h>
#include <string.h>

#include "config.h"

#ifndef CONFIG_HAS_STRLCPY
extern size_t strlcpy(char *dest, const char *src, size_t size);
#endif

#ifndef CONFIG_HAS_STRLCAT
extern size_t strlcat(char *dest, const char *src, size_t count);
#endif

#endif /* __CPT2_STRING_H__ */
