#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <arpa/inet.h>

#include "compiler.h"
#include "string.h"

char *vprintip(int family, void *addr, char *buf, size_t size)
{
	if (!addr || !buf || size < 1)
		return NULL;

	switch (family) {
	case PF_INET:
		inet_ntop(PF_INET, (void *)&((struct sockaddr_in *)addr)->sin_addr, buf, size);
		break;
	case PF_INET6:
		inet_ntop(PF_INET6, (void *)&((struct sockaddr_in6 *)addr)->sin6_addr, buf, size);
		break;
	default:
		strlcpy(buf, "@unknown", size);
		break;
	}
	return buf;
}

char *vprinthex(char *dst, size_t size, void *src, size_t len)
{
	static const char hex[] = "0123456789abcdef";
	unsigned char *s = src;
	size_t i, j = 0;

	if (size > 2) {
		for (i = 0; i < len && j < size - 2; i++) {
			dst[j++] = hex[s[i] >>  4];
			dst[j++] = hex[s[i] & 0xf];
		}
	}
	dst[min(j, (size ? size - 1 : 0))] = '\0';
	return dst;
}
