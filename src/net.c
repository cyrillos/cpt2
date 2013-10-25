#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_addr.h>

#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "libnetlink.h"
#include "cpt-image.h"
#include "hashtable.h"
#include "xmalloc.h"
#include "socket.h"
#include "string.h"
#include "image.h"
#include "mslab.h"
#include "read.h"
#include "task.h"
#include "util.h"
#include "net.h"
#include "log.h"
#include "obj.h"

#include "protobuf.h"
#include "protobuf/netdev.pb-c.h"
#include "protobuf/tun.pb-c.h"

/*
 * Magic numbers from iproute2 source code.
 * Will need them for iptool dumb output.
 */
static const u32 IFADDR_DUMP_MAGIC = 0x47361222;
static const u32 ROUTE_DUMP_MAGIC = 0x45311224;


#define NET_HASH_BITS		10
static DEFINE_HASHTABLE(netdev_hash, NET_HASH_BITS);

static LIST_HEAD(netdev_list);
static LIST_HEAD(ifaddr_list);

struct netdev_struct *netdev_lookup(u32 cpt_index)
{
	struct netdev_struct *dev;

	hash_for_each_key(netdev_hash, dev, hash, cpt_index) {
		if (dev->ni.cpt_index == cpt_index)
			return dev;
	}

	return NULL;
}

/*
 * There are some routes OpenVZ skips on restore. Thus
 * do the same in converter.
 */
static int should_skip_route(struct nlmsghdr *nlh)
{
	int min_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	struct rtmsg *rtm = NLMSG_DATA(nlh);
	u32 prefix0 = 0;

	if (nlh->nlmsg_len > min_len) {
		int attrlen = nlh->nlmsg_len - NLMSG_ALIGN(min_len);
		struct rtattr *rta = (void *)nlh + NLMSG_ALIGN(min_len);

		while (RTA_OK(rta, attrlen)) {
			switch (rta->rta_type) {
			case RTA_DST:
				prefix0 = *(u32 *)RTA_DATA(rta);
				break;
			/*
			 * FIXME we ignore IFA_CACHEINFO info on restore,
			 * thus simply drop such routes.
			 */
			case RTA_CACHEINFO:
				return 1;
			}
			if (rta->rta_type == RTA_DST)
				prefix0 = *(u32 *)RTA_DATA(rta);
			rta = RTA_NEXT(rta, attrlen);
		}
	}

	if (rtm->rtm_family == AF_INET6) {
		if (rtm->rtm_type == RTN_LOCAL)
			return 1;
		if (rtm->rtm_flags & RTM_F_CLONED)
			return 1;
		if (rtm->rtm_protocol == RTPROT_UNSPEC		||
		    rtm->rtm_protocol == RTPROT_RA		||
		    rtm->rtm_protocol == RTPROT_REDIRECT	||
		    rtm->rtm_protocol == RTPROT_KERNEL)
			return 1;
		if (rtm->rtm_protocol == RTPROT_BOOT) {
			if ((rtm->rtm_dst_len ==  8 && prefix0 == htonl(0xFF000000)) ||
			    (rtm->rtm_dst_len == 64 && prefix0 == htonl(0xFE800000)))
			return 1;
		}
	}

#if 0
	if (rtm->rtm_protocol == RTPROT_KERNEL)
		return 1;
#endif

	return 0;
}

int write_routes(context_t *ctx)
{
#if 1
	int fd = fdset_fd(ctx->fdset_netns, CR_FD_ROUTE);
	u32 magic = ROUTE_DUMP_MAGIC;
	char data[PAGE_SIZE];
	off_t start, end;

	if (write_data(fd, &magic, sizeof(magic))) {
		pr_err("Failed to write route magic\n");
		return -1;
	}

	/*
	 * OpenVZ save routes in plain netlink stream. Still we
	 * need to align data thus ip tool in CRIU would understand it.
	 */
	get_section_bounds(ctx, CPT_SECT_NET_ROUTE, &start, &end);
	while (start < end) {
		struct cpt_object_hdr v;
		off_t from, to;

		if (read_obj_cpt(ctx->fd, CPT_OBJ_NET_ROUTE, &v, start)) {
			pr_err("Can't read route object at @%li\n", (long)start);
			return -1;
		}

		from	= start + v.cpt_hdrlen;
		to	= start + v.cpt_next;

		while (from < to) {
			struct nlmsghdr *nh = (void *)data;
			struct nlmsghdr *n = &nh[1];
			size_t size;

			if (__read_ptr_at(ctx->fd, nh, from)) {
				pr_err("Can't read nlmsghdr at @%li\n", (long)from);
				return -1;
			}

			size = NLMSG_ALIGN(nh->nlmsg_len);
			if (!size)
				break;

			if (size > sizeof(data)) {
				pr_err("The nlmsg length is too big %d at @%li\n",
				       (int)size, (long)from);
				return -1;
			}

			if (__read(ctx->fd, n, nh->nlmsg_len)) {
				pr_err("Can't read nlmsghdr at @%li\n", (long)from);
				return -1;
			}

			if (!should_skip_route(nh)) {
				/*
				 * Write data back to image.
				 */
				if (write_data(fd, data, size)) {
					pr_perror("Can't write nlmsghdr at @%li", (long)from);
					return -1;
				}
			}

			from += size;
		}

		start += v.cpt_next;
	}
	return 0;
#else
	int fd = fdset_fd(ctx->fdset_netns, CR_FD_ROUTE);
	u32 magic = ROUTE_DUMP_MAGIC;

	if (write_data(fd, &magic, sizeof(magic))) {
		pr_err("Failed to write route magic\n");
		return -1;
	}
	return 0;
#endif
}

void free_netdevs(context_t *ctx)
{
	struct netdev_struct *dev, *tmp;

	list_for_each_entry_safe(dev, tmp, &netdev_list, list) {
		obj_unhash_to(dev);
		obj_free_to(dev);
	}
}

static int write_tundev(context_t *ctx, struct netdev_struct *dev)
{
	int fd = fdset_fd(ctx->fdset_glob, CR_FD_TUNFILE);
	TunfileEntry tfe = TUNFILE_ENTRY__INIT;
	struct file_struct *file;

	file = obj_lookup_to(CPT_OBJ_FILE, dev->u.tti.cpt_bindfile);
	if (!file) {
		pr_err("Can't find file @%li associated with tun\n",
		       (long)dev->u.tti.cpt_bindfile);
		return -1;
	}

	tfe.id			= obj_id_of(file);
	tfe.netdev		= (char *)dev->ni.cpt_name;

	/*
	 * FIXME These are not in cpt image :(
	 */
	tfe.has_detached	= true;
	tfe.detached		= false;

	return pb_write_one(fd, &tfe, PB_TUNFILE);
}

static int write_netdev(context_t *ctx, struct netdev_struct *dev)
{
	NetDeviceEntry netdev = NET_DEVICE_ENTRY__INIT;
	TunLinkEntry tun = TUN_LINK_ENTRY__INIT;
	int fd = fdset_fd(ctx->fdset_netns, CR_FD_NETDEV);
	int ret = 0;

	/*
	 * Best type match is by @dev->utype, but it's not
	 * always available.
	 */
	switch (dev->utype) {
	case CPT_OBJ_NET_TUNTAP:
		netdev.type = ND_TYPE__TUN;
		break;
	case CPT_OBJ_NET_VETH:
		netdev.type = ND_TYPE__VETH;
		break;
	default:
		if (!strncmp((char *)dev->ni.cpt_name, "lo", 2))
			netdev.type = ND_TYPE__LOOPBACK;
		else if (!strncmp((char *)dev->ni.cpt_name, "venet", 5))
			netdev.type = ND_TYPE__EXTLINK;
		else {
			pr_err("Unsupported netdevice `%s'\n",
			       dev->ni.cpt_name);
			return -1;
		}
		break;
	}

	netdev.ifindex	= dev->ni.cpt_index;
	netdev.mtu	= dev->ni.cpt_mtu;
	netdev.flags	= dev->ni.cpt_flags;
	netdev.name	= (char *)dev->ni.cpt_name;

	switch ((int)netdev.type) {
	case ND_TYPE__TUN:
		ret = write_tundev(ctx, dev);

		/*
		 * FIXME No @vnethdr, @sndbuf, @group in image.
		 * While for @vnethdr and @sndbuf we simply
		 * pick up values present in some real CRIU
		 * dump image, @group is set to -1, just like
		 * OpenVZ kernel does.
		 */

		netdev.tun	= &tun;
		tun.flags	= dev->u.tti.cpt_flags;
		tun.owner	= dev->u.tti.cpt_owner;
		tun.group	= -1;
		tun.sndbuf	= 0x7fffffff;
		tun.vnethdr	= 0xa;
		break;
	}

	ret |= pb_write_one(fd, &netdev, PB_NETDEV);

	return ret;
}

int write_netdevs(context_t *ctx)
{
	struct netdev_struct *dev;

	list_for_each_entry(dev, &netdev_list, list) {
		if (write_netdev(ctx, dev))
			return -1;
	}

	return 0;
}

static void show_netdev_cont(context_t *ctx, struct netdev_struct *dev)
{
	char hexbuf[128];
	unsigned int i;

	pr_debug("\t@%-10li index %#8x flags %#8x mtu %#8x -> %s\n",
		 obj_pos_of(dev), dev->ni.cpt_index,
		 dev->ni.cpt_flags, dev->ni.cpt_mtu, dev->ni.cpt_name);

	pr_debug("\t\tmac:\n\t\t");
	vprinthex(hexbuf, sizeof(hexbuf), dev->hwi.cpt_dev_addr, sizeof(dev->hwi.cpt_dev_addr));
	for (i = 0; hexbuf[i]; i += 2) {
		pr_debug("%c%c:", hexbuf[i + 0], hexbuf[i + 1]);
		if (((i + 2) % 16) == 0 && hexbuf[i + 2])
			pr_debug("\n\t\t");
	}
	pr_debug("\n");

	switch (dev->utype) {
	case CPT_OBJ_NET_TUNTAP:
		vprinthex(hexbuf, sizeof(hexbuf), dev->u.tti.cpt_dev_addr, sizeof(dev->u.tti.cpt_dev_addr));
		pr_debug("\t\ttun/tap: owner #%8x flags %#-8lx bindfile @%li\n"
			 "\t\t         if_flags %#-8lx cpt_dev_addr ",
			 dev->u.tti.cpt_owner, (long)dev->u.tti.cpt_flags,
			 (long)dev->u.tti.cpt_bindfile, (long)dev->u.tti.cpt_if_flags);
		for (i = 0; hexbuf[i]; i += 2)
			pr_debug("%c%c:", hexbuf[i + 0], hexbuf[i + 1]);
		pr_debug("\n");
		break;
	}
}

static int read_netdev_payload(context_t *ctx, struct netdev_struct *dev, off_t start, off_t end)
{
	struct cpt_object_hdr hdr = { };

	for (; start < end; start += hdr.cpt_next) {
		if (read_obj_hdr(ctx->fd, &hdr, start)) {
			pr_err("Can't read header at @%li\n", (long)start);
			return -1;
		}

		switch (hdr.cpt_object) {
		case CPT_OBJ_NET_HWADDR:
			memcpy((void *)&dev->hwi, &hdr, sizeof(hdr));
			if (read_obj_cont(ctx->fd, &dev->hwi))
				goto cont_failed;
			break;
		case CPT_OBJ_NET_TUNTAP:
			memcpy((void *)&dev->u.tti, &hdr, sizeof(hdr));
			if (read_obj_cont(ctx->fd, &dev->u.tti))
				goto cont_failed;
			dev->utype = CPT_OBJ_NET_TUNTAP;
			if (dev->u.tti.cpt_next > dev->u.tti.cpt_hdrlen) {
				/*
				 * FIXME Here might be CPT_OBJ_NET_TAP_FILTER.
				 * We don't support it in criu yet but ignore
				 * here for a while.
				 */
				pr_debug("TUN/TAP filter detected at @%li, ignoring\n",
					 (long)start);
			}
			break;
		case CPT_OBJ_NET_STATS:
		case CPT_OBJ_NET_IPIP_TUNNEL:
		case CPT_OBJ_NET_BR:
			/*
			 * We don't support this objects yet,
			 * so skip them for a while.
			 */
			break;
		case CPT_OBJ_NET_VETH:
			memcpy((void *)&dev->u.vti, &hdr, sizeof(hdr));
			if (read_obj_cont(ctx->fd, &dev->u.vti))
				goto cont_failed;
			dev->utype = CPT_OBJ_NET_VETH;
			break;
		default:
			pr_err("Bad object %s at @%li\n",
			       obj_name(hdr.cpt_object), (long)start);
			return -1;
		}
	}

	return 0;

cont_failed:
	pr_err("Can't read object at @%li\n", (long)start);
	return -1;
}

int read_netdevs(context_t *ctx)
{
	off_t start, end;

	pr_read_start("net devices\n");
	get_section_bounds(ctx, CPT_SECT_NET_DEVICE, &start, &end);

	while (start < end) {
		struct netdev_struct *dev;

		dev = obj_alloc_to(struct netdev_struct, ni);
		if (!dev)
			return -1;

		if (read_obj_cpt(ctx->fd, CPT_OBJ_NET_DEVICE, &dev->ni, start)) {
			obj_free_to(dev);
			pr_err("Can't read netdev object at @%li\n", (long)start);
			return -1;
		}

		memzero(&dev->u, sizeof(dev->u));
		memzero(&dev->hwi, sizeof(dev->hwi));
		memzero(&dev->nsi, sizeof(dev->nsi));
		dev->utype = OBJ_ANY;

		INIT_LIST_HEAD(&dev->list);
		INIT_HLIST_NODE(&dev->hash);
		obj_set_eos(dev->ni.cpt_name);

		hash_add(netdev_hash, &dev->hash, dev->ni.cpt_index);
		list_add_tail(&dev->list, &netdev_list);

		obj_hash_typed_to(dev, CPT_OBJ_NET_DEVICE, start);

		if (read_netdev_payload(ctx, dev, start + dev->ni.cpt_hdrlen,
					start + dev->ni.cpt_next)) {
			obj_free_to(dev);
			pr_err("Can't read netdev object payload at @%li\n",
			       (long)start);
			return -1;
		}

		start += dev->ni.cpt_next;

		show_netdev_cont(ctx, dev);
	}
	pr_read_end();

	return 0;
}

void free_ifaddr(context_t *ctx)
{
	struct ifaddr_struct *ifa, *t;

	list_for_each_entry_safe(ifa, t, &ifaddr_list, list)
		obj_free_to(ifa);
}

int write_ifaddr(context_t *ctx)
{
	int fd = fdset_fd(ctx->fdset_netns, CR_FD_IFADDR);
	u32 magic = IFADDR_DUMP_MAGIC;
	struct ifaddr_struct *ifa;

	if (write_data(fd, &magic, sizeof(magic))) {
		pr_err("Failed to write ifaddr magic\n");
		return -1;
	}

	list_for_each_entry(ifa, &ifaddr_list, list) {
		struct ifaddrmsg *ifm;
		struct nlmsghdr *nlh;
		char buf[8192];
		mslab_t *m;

		m = mslab_cast(buf, sizeof(buf));

#if 0
		/*
		 * FIXME Only "lo" and "tun" supported at the moment.
		 */
		if (memcmp((char *)ifa->ii.cpt_label, "lo", 2) &&
		    memcmp((char *)ifa->ii.cpt_label, "tun", 3)) {
			pr_warn("Internet address for device %s skipped\n",
				(char *)ifa->ii.cpt_label);
			continue;
		}
#endif

		nlh = nlmsg_put(m, 0, 0, RTM_NEWADDR, sizeof(*ifm), NLM_F_MULTI);
		BUG_ON(!nlh);

		ifm = nlmsg_data(nlh);
		ifm->ifa_index		= ifa->ii.cpt_index;
		ifm->ifa_family		= ifa->ii.cpt_family;
		ifm->ifa_prefixlen	= ifa->ii.cpt_masklen;
		ifm->ifa_flags		= ifa->ii.cpt_flags;
		ifm->ifa_scope		= ifa->ii.cpt_scope;

		if (ifa->ii.cpt_family == PF_INET) {
			nla_put(m, IFA_ADDRESS, sizeof(ifa->ii.cpt_peer[0]), ifa->ii.cpt_peer);
			nla_put(m, IFA_LOCAL, sizeof(ifa->ii.cpt_address[0]), ifa->ii.cpt_address);
			nla_put(m, IFA_BROADCAST, sizeof(ifa->ii.cpt_broadcast[0]), ifa->ii.cpt_broadcast);
			nla_put_string(m, IFA_LABEL, (const char *)ifa->ii.cpt_label);
		} else if (ifa->ii.cpt_family == PF_INET6) {
			nla_put(m, IFA_ADDRESS, sizeof(ifa->ii.cpt_peer), ifa->ii.cpt_peer);
		} else
			BUG();
		nlmsg_end(m, nlh);

		/*
		 * FIXME No IFA_CACHEINFO at moment, do we need it at all?
		 * It's present in image
		 */

		if (write_data(fd, mslab_payload_pointer(m),
			       mslab_payload_size(m))) {
			pr_err("Failed to write ifaddrmsg\n");
			return -1;
		}
	}

	return 0;
}

static void show_ifaddr_cont(context_t *ctx, struct ifaddr_struct *ifa)
{
	char buf[max(INET_ADDRSTRLEN, INET6_ADDRSTRLEN)];
	char hexbuf[128];
	unsigned int i;

	pr_debug("\t@%-10li index %#8x family %8s masklen %#1x "
		 "flags %#1x scope %#1x -> %s", obj_pos_of(ifa),
		 ifa->ii.cpt_index, sock_proto_family(ifa->ii.cpt_family),
		 (int)ifa->ii.cpt_masklen, (int)ifa->ii.cpt_flags,
		 (int)ifa->ii.cpt_scope, (char *)ifa->ii.cpt_label);

	vprinthex(hexbuf, sizeof(hexbuf), ifa->ii.cpt_address, sizeof(ifa->ii.cpt_address));
	pr_debug("\n\t\t\t");
	for (i = 0; hexbuf[i]; i += 2) {
		pr_debug("%c%c:", hexbuf[i + 0], hexbuf[i + 1]);
		if (((i + 2) % 16) == 0 && hexbuf[i + 2])
			pr_debug("\n\t\t\t");
	}
	pr_debug("\n\t\t\t\taddress   --> %s", vprintip(ifa->ii.cpt_family, ifa->ii.cpt_address, buf, sizeof(buf)));

	vprinthex(hexbuf, sizeof(hexbuf), ifa->ii.cpt_peer, sizeof(ifa->ii.cpt_peer));
	pr_debug("\n\t\t\t");
	for (i = 0; hexbuf[i]; i += 2) {
		pr_debug("%c%c:", hexbuf[i + 0], hexbuf[i + 1]);
		if (((i + 2) % 16) == 0 && hexbuf[i + 2])
			pr_debug("\n\t\t\t");
	}
	pr_debug("\n\t\t\t\tpeer      --> %s", vprintip(ifa->ii.cpt_family, ifa->ii.cpt_peer, buf, sizeof(buf)));

	vprinthex(hexbuf, sizeof(hexbuf), ifa->ii.cpt_broadcast, sizeof(ifa->ii.cpt_broadcast));
	pr_debug("\n\t\t\t");
	for (i = 0; hexbuf[i]; i += 2) {
		pr_debug("%c%c:", hexbuf[i + 0], hexbuf[i + 1]);
		if (((i + 2) % 16) == 0 && hexbuf[i + 2])
			pr_debug("\n\t\t\t");
	}
	pr_debug("\n\t\t\t\tbroadcast --> %s", vprintip(ifa->ii.cpt_family, ifa->ii.cpt_broadcast, buf, sizeof(buf)));
	pr_debug("\n");
}

int read_ifaddr(context_t *ctx)
{
	off_t start, end;

	pr_read_start("net interface addresses\n");
	get_section_bounds(ctx, CPT_SECT_NET_IFADDR, &start, &end);

	while (start < end) {
		struct ifaddr_struct *ifa;

		ifa = obj_alloc_to(struct ifaddr_struct, ii);
		if (!ifa)
			return -1;

		if (read_obj_cpt(ctx->fd, CPT_OBJ_NET_IFADDR, &ifa->ii, start)) {
			pr_err("Can't read netdev object at @%li\n", (long)start);
			obj_free_to(ifa);
			return -1;
		}

		/*
		 * Check for valid data. Net device must be read already.
		 */
		if (ifa->ii.cpt_family != PF_INET &&
		    ifa->ii.cpt_family != PF_INET6) {
			pr_err("Usupported family %u at @%li\n",
			       (unsigned int)ifa->ii.cpt_family, (long)start);
			obj_free_to(ifa);
			return -1;
		}

		if (!netdev_lookup(ifa->ii.cpt_index)) {
			pr_err("No net device with index %#x at @%li\n",
			       ifa->ii.cpt_index, (long)start);
			obj_free_to(ifa);
			return -1;
		}

		INIT_LIST_HEAD(&ifa->list);
		obj_set_eos(ifa->ii.cpt_label);

		list_add_tail(&ifa->list, &ifaddr_list);

		obj_hash_typed_to(ifa, CPT_OBJ_NET_IFADDR, start);
		start += ifa->ii.cpt_next;

		show_ifaddr_cont(ctx, ifa);
	}
	pr_read_end();

	return 0;
}
