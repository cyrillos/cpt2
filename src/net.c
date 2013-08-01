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
#include "image.h"
#include "mslab.h"
#include "read.h"
#include "task.h"
#include "net.h"
#include "log.h"
#include "obj.h"

#include "protobuf.h"
#include "protobuf/netdev.pb-c.h"

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

#if 0
int write_routes(context_t *ctx)
{
	int fd = fdset_fd(ctx->fdset_ns, CR_FD_ROUTE);
	u32 magic = ROUTE_DUMP_MAGIC;
	int p[2], ret = -1;
	off_t start, end;

	if (write_data(fd, &magic, sizeof(magic))) {
		pr_err("Failed to write route magic\n");
		return -1;
	}

	if (pipe(p)) {
		pr_perror("Can't create pipe");
		return -1;
	}

	/*
	 * OpenVZ save routes in plain netlink stream so
	 * just copy it to output.
	 */
	get_section_bounds(ctx, CPT_SECT_NET_ROUTE, &start, &end);

	while (start < end) {
		struct cpt_object_hdr v;

		if (read_obj_cpt(ctx->fd, CPT_OBJ_NET_ROUTE, &v, start)) {
			pr_err("Can't read route object at @%li\n", (long)start);
		}

		if (v.cpt_next > v.cpt_hdrlen) {
			ssize_t ret_in, ret_out, len;

			len = v.cpt_next - v.cpt_hdrlen;
			ret_in = splice(ctx->fd, NULL, p[1], NULL, len, SPLICE_F_MOVE);
			if (ret_in < 0) {
				pr_perror("Can't splice %li bytes", (long)len);
				goto out;
			}

			ret_out = splice(p[0], NULL, fd, NULL, len, SPLICE_F_MOVE);
			if (ret_out < 0) {
				pr_perror("Can't splice %li bytes", (long)len);
				goto out;
			}

			if (ret_in != len || ret_out != len) {
				pr_err("Splice only %li/%li bytes while %li expected\n",
				       (long)ret_in, (long)ret_out, (long)len);
				goto out;
			}
		}
		start += v.cpt_next;
	}
	ret = 0;

out:
	close(p[0]);
	close(p[1]);
	return ret;
}
#else
int write_routes(context_t *ctx)
{
	int fd = fdset_fd(ctx->fdset_ns, CR_FD_ROUTE);
	u32 magic = ROUTE_DUMP_MAGIC;

	if (write_data(fd, &magic, sizeof(magic))) {
		pr_err("Failed to write route magic\n");
		return -1;
	}

	return 0;
}
#endif

void free_netdevs(context_t *ctx)
{
	struct netdev_struct *dev, *tmp;

	list_for_each_entry_safe(dev, tmp, &netdev_list, list) {
		obj_unhash_to(dev);
		obj_free_to(dev);
	}
}

static int write_netdev(context_t *ctx, struct netdev_struct *dev)
{
	NetDeviceEntry netdev = NET_DEVICE_ENTRY__INIT;
	int fd = fdset_fd(ctx->fdset_ns, CR_FD_NETDEV);

	if (!strncmp((char *)dev->ni.cpt_name, "lo", 2))
		netdev.type = ND_TYPE__LOOPBACK;
	else if (!strncmp((char *)dev->ni.cpt_name, "veth", 4))
		netdev.type = ND_TYPE__VETH;
	else if (!strncmp((char *)dev->ni.cpt_name, "venet", 5)) {
		pr_info("Netdevice `%s' detected, ignore\n", dev->ni.cpt_name);
		return 0;
	} else {
		pr_err("Unsupported netdevice `%s'\n",
		       dev->ni.cpt_name);
		return -1;
	}

	netdev.ifindex	= dev->ni.cpt_index;
	netdev.mtu	= dev->ni.cpt_mtu;
	netdev.flags	= dev->ni.cpt_flags;
	netdev.name	= (char *)dev->ni.cpt_name;

	return pb_write_one(fd, &netdev, PB_NETDEV);
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
	unsigned int i;

	pr_debug("\t@%-10li index %#8x flags %#8x mtu %#8x -> %s\n",
		 obj_pos_of(dev), dev->ni.cpt_index,
		 dev->ni.cpt_flags, dev->ni.cpt_mtu, dev->ni.cpt_name);

	pr_debug("\t\tmac: ");
	for (i = 0; i < sizeof(dev->hwi.cpt_dev_addr) - 2; i++)
		pr_debug("%x:", (int)dev->hwi.cpt_dev_addr[i]);
	pr_debug("%x\n", (int)dev->hwi.cpt_dev_addr[i]);
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

		/*
		 * Netdevice is stored as an array of objects,
		 * where netdev comes first, then mac address,
		 * and finally -- device statistics. Since we
		 * don't deal with statistics, we simply skip
		 * it.
		 */

		if (read_obj_cpt(ctx->fd, CPT_OBJ_NET_DEVICE, &dev->ni, start)) {
			obj_free_to(dev);
			pr_err("Can't read netdev object at @%li\n", (long)start);
			return -1;
		}

		if (read_obj_cpt(ctx->fd, CPT_OBJ_NET_HWADDR, &dev->hwi,
				 start + dev->ni.cpt_hdrlen)) {
			obj_free_to(dev);
			pr_err("Can't read netdev object at @%li\n", (long)start);
			return -1;
		}

		INIT_LIST_HEAD(&dev->list);
		INIT_HLIST_NODE(&dev->hash);
		obj_set_eos(dev->ni.cpt_name);

		hash_add(netdev_hash, &dev->hash, dev->ni.cpt_index);
		list_add_tail(&dev->list, &netdev_list);

		obj_hash_typed_to(dev, CPT_OBJ_NET_DEVICE, start);
		start += dev->ni.cpt_next;

		/*
		 * Here might be device statistics, just skip
		 * it since we don't deal with it anyway.
		 */
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
	int fd = fdset_fd(ctx->fdset_ns, CR_FD_IFADDR);
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

		/*
		 * FIXME Only "lo" supported at the moment.
		 */
		if (strcmp((char *)ifa->ii.cpt_label, "lo")) {
			pr_warn("Internet address for device %s skipped\n",
				(char *)ifa->ii.cpt_label);
			continue;
		}

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
	pr_debug("\t@%-10li index %#8x family %8s masklen %#1x "
		 "flags %#1x scope %#1x -> %s\n", obj_pos_of(ifa),
		 ifa->ii.cpt_index, sock_proto_family(ifa->ii.cpt_family),
		 (int)ifa->ii.cpt_masklen, (int)ifa->ii.cpt_flags,
		 (int)ifa->ii.cpt_scope, (char *)ifa->ii.cpt_label);
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
