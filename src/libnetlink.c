#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "libnetlink.h"

void *nlmsg_data(const struct nlmsghdr *nlh)
{
	return (unsigned char *)nlh + NLMSG_HDRLEN;
}

int nlmsg_msg_size(int payload)
{
	return NLMSG_HDRLEN + payload;
}

int nlmsg_total_size(int payload)
{
	return NLMSG_ALIGN(nlmsg_msg_size(payload));
}

static struct nlmsghdr *__nlmsg_put(mslab_t *m, int portid, int seq,
				    int type, int len, int flags)
{
	int size = nlmsg_msg_size(len);
	struct nlmsghdr *nlh;

	nlh = (struct nlmsghdr *)mslab_put(m, NLMSG_ALIGN(size));
	nlh->nlmsg_type	= type;
	nlh->nlmsg_len	= size;
	nlh->nlmsg_flags= flags;
	nlh->nlmsg_pid	= portid;
	nlh->nlmsg_seq	= seq;

	if ((NLMSG_ALIGN(size) - size))
		memset(nlmsg_data(nlh) + len, 0, NLMSG_ALIGN(size) - size);

	return nlh;
}

struct nlmsghdr *nlmsg_put(mslab_t *m, int portid, int seq,
			   int type, int payload, int flags)
{
	if (unlikely(mslab_tail_room(m) < nlmsg_total_size(payload)))
		return NULL;

	return __nlmsg_put(m, portid, seq, type, payload, flags);
}

int nlmsg_end(mslab_t *m, struct nlmsghdr *nlh)
{
	nlh->nlmsg_len = mslab_tail_pointer(m) - (void *)nlh;
	return mslab_payload_size(m);
}

int nla_attr_size(int payload)
{
	return NLA_HDRLEN + payload;
}

int nla_total_size(int payload)
{
	return NLA_ALIGN(nla_attr_size(payload));
}

int nla_padlen(int payload)
{
	return nla_total_size(payload) - nla_attr_size(payload);
}

void *nla_data(const struct nlattr *nla)
{
	return (char *)nla + NLA_HDRLEN;
}

static struct nlattr *__nla_reserve(mslab_t *m, int attrtype, int attrlen)
{
	struct nlattr *nla;

	nla = (struct nlattr *)mslab_put(m, nla_total_size(attrlen));
	nla->nla_type	= attrtype;
	nla->nla_len	= nla_attr_size(attrlen);

	memset((unsigned char *)nla + nla->nla_len, 0, nla_padlen(attrlen));
	return nla;
}

static void __nla_put(mslab_t *m, int attrtype, int attrlen, const void *data)
{
	struct nlattr *nla = __nla_reserve(m, attrtype, attrlen);
	memcpy(nla_data(nla), data, attrlen);
}

int nla_put(mslab_t *m, int attrtype, int attrlen, const void *data)
{
	if (unlikely(mslab_tail_room(m) < nla_total_size(attrlen)))
		return -EMSGSIZE;

	__nla_put(m, attrtype, attrlen, data);
	return 0;
}

int nla_put_string(mslab_t *m, int attrtype, const char *str)
{
	return nla_put(m, attrtype, strlen(str) + 1, str);
}
