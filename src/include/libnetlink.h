#ifndef __CR_LIBNETLINK_H__
#define __CR_LIBNETLINK_H__

#include <sys/types.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "compiler.h"
#include "mslab.h"

extern void *nlmsg_data(const struct nlmsghdr *nlh);
extern int nlmsg_msg_size(int payload);
extern int nlmsg_total_size(int payload);
extern struct nlmsghdr *nlmsg_put(mslab_t *m, int portid,
				  int seq, int type,
				  int payload, int flags);
extern int nlmsg_end(mslab_t *m, struct nlmsghdr *nlh);

extern int nla_attr_size(int payload);
extern int nla_total_size(int payload);
extern int nla_padlen(int payload);
extern void *nla_data(const struct nlattr *nla);
extern int nla_put(mslab_t *m, int attrtype, int attrlen, const void *data);
extern int nla_put_string(mslab_t *m, int attrtype, const char *str);

#endif /* __CR_LIBNETLINK_H__ */
