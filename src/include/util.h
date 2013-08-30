#ifndef __CPT2_UTIL_H__
#define __CPT2_UTIL_H__

#include <sys/types.h>

extern char *vprinthex(char *dst, size_t size, void *src, size_t len);
extern char *vprintip_sin(int family, void *addr, char *buf, size_t size);
extern char *vprintip(int family, void *addr, char *buf, size_t size);

#endif /* __CPT2_UTIL_H__ */
