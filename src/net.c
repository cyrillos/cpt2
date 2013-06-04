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
#include "image.h"
#include "mslab.h"
#include "read.h"
#include "task.h"
#include "net.h"
#include "log.h"
#include "obj.h"

#include "protobuf.h"
#include "protobuf/netdev.pb-c.h"
#include "protobuf/sk-unix.pb-c.h"
#include "protobuf/sk-inet.pb-c.h"
#include "protobuf/sk-netlink.pb-c.h"

/*
 * Magic numbers from iproute2 source code.
 * Will need them for iptool dumb output.
 */
static const u32 IFADDR_DUMP_MAGIC = 0x47361222;
static const u32 ROUTE_DUMP_MAGIC = 0x45311224;

#define NET_HASH_BITS		10
static DEFINE_HASHTABLE(sock_hash, NET_HASH_BITS);
static DEFINE_HASHTABLE(sock_index_hash, NET_HASH_BITS);
static DEFINE_HASHTABLE(netdev_hash, NET_HASH_BITS);

static LIST_HEAD(netdev_list);
static LIST_HEAD(ifaddr_list);

#define PB_ALEN_INET	1
#define PB_ALEN_INET6	4

struct sock_struct *sk_lookup_file(u64 cpt_file)
{
	struct sock_struct *sk;

	hash_for_each_key(sock_hash, sk, hash, cpt_file) {
		if (sk->si.cpt_file == cpt_file)
			return sk;
	}

	return NULL;
}

struct sock_struct *sk_lookup_index(u32 cpt_index)
{
	struct sock_struct *sk;

	hash_for_each_key(sock_index_hash, sk, index_hash, cpt_index) {
		if (sk->si.cpt_index == cpt_index)
			return sk;
	}

	return NULL;
}

struct netdev_struct *netdev_lookup(u32 cpt_index)
{
	struct netdev_struct *dev;

	hash_for_each_key(netdev_hash, dev, hash, cpt_index) {
		if (dev->ni.cpt_index == cpt_index)
			return dev;
	}

	return NULL;
}

static bool can_dump_unix_sk(const struct sock_struct *sk)
{
	if (sk->si.cpt_type != SOCK_STREAM &&
	    sk->si.cpt_type != SOCK_DGRAM) {
		pr_err("Only stream/dgram sockets supported, "
			"but type %d found on socket at @%li\n",
		       (int)sk->si.cpt_type, obj_pos_of(sk));
		return false;
	}

	switch (sk->si.cpt_state) {
	case TCP_LISTEN:
	case TCP_ESTABLISHED:
	case TCP_CLOSE:
		break;
	default:
		pr_err("Unknown state %d on socket at @%li\n",
		       sk->si.cpt_state, obj_pos_of(sk));
		return 0;
	}

	return true;
}

static int fill_socket_opts(context_t *ctx,
			    const struct sock_struct *sk,
			    SkOptsEntry *skopts)
{
	sk_opts_entry__init(skopts);

	skopts->so_sndbuf	= sk->si.cpt_sndbuf;
	skopts->so_rcvbuf	= sk->si.cpt_rcvbuf;

	skopts->has_so_priority	= true;
	skopts->so_priority	= sk->si.cpt_priority;

	skopts->has_so_rcvlowat	= true;
	skopts->so_rcvlowat	= sk->si.cpt_rcvlowat;

	/* FIXME No so_mark in image */
	skopts->has_so_mark	= false;

	if (sk->si.cpt_sndtimeo == MAX_SCHEDULE_TIMEOUT) {
		skopts->so_snd_tmo_sec = 0;
		skopts->so_snd_tmo_usec = 0;
	} else {
		skopts->so_snd_tmo_sec = sk->si.cpt_sndtimeo / ctx->h.cpt_hz;
		skopts->so_snd_tmo_usec = ((sk->si.cpt_sndtimeo % ctx->h.cpt_hz) * 1000000) / ctx->h.cpt_hz;
	}

	if (sk->si.cpt_sndtimeo == MAX_SCHEDULE_TIMEOUT) {
		skopts->so_rcv_tmo_sec = 0;
		skopts->so_rcv_tmo_usec = 0;
	} else {
		skopts->so_rcv_tmo_sec = sk->si.cpt_rcvtimeo / ctx->h.cpt_hz;
		skopts->so_rcv_tmo_usec = ((sk->si.cpt_rcvtimeo % ctx->h.cpt_hz) * 1000000) / ctx->h.cpt_hz;
	}

	skopts->has_reuseaddr		= true;
	skopts->reuseaddr		= sk->si.cpt_reuse ? true : false;

	skopts->has_so_passcred		= true;
	skopts->so_passcred		= !!(sk->si.cpt_ssflags & (1 << SOCK_PASSCRED));

	skopts->has_so_passsec		= true;
	skopts->so_passsec		= !!(sk->si.cpt_ssflags & (1 << SOCK_PASSSEC));

	skopts->has_so_dontroute		= true;
	skopts->so_dontroute		= !!(sk->si.cpt_flags & (1 << SOCK_LOCALROUTE));

	skopts->has_so_no_check		= true;
	skopts->so_no_check		= sk->si.cpt_no_check;

	if (sk->si.cpt_bound_dev_if) {
		struct netdev_struct *dev = netdev_lookup(sk->si.cpt_bound_dev_if);
		if (!dev) {
			pr_err("No net device with index %#x found\n",
				sk->si.cpt_bound_dev_if);
			return -1;
		}

		skopts->so_bound_dev = (char *)dev->ni.cpt_name;
	}

	return 0;
}

static struct cpt_inode_image *socket_inode(struct sock_struct *sk)
{
	struct file_struct *file;

	if (sk->si.cpt_file == -1)
		return NULL;

	file = obj_lookup_to(CPT_OBJ_FILE, sk->si.cpt_file);
	if (file) {
		if (file->fi.cpt_inode == -1)
			return NULL;
		return obj_lookup_img(CPT_OBJ_INODE, file->fi.cpt_inode);
	}

	return NULL;
}

static int write_unix_socket(context_t *ctx,
			     struct file_struct *file,
			     struct sock_struct *sk)
{
	FilePermsEntry perms = FILE_PERMS_ENTRY__INIT;
	SkOptsEntry skopts = SK_OPTS_ENTRY__INIT;
	UnixSkEntry ue = UNIX_SK_ENTRY__INIT;
	FownEntry fown = FOWN_ENTRY__INIT;

	int fd = fdset_fd(ctx->fdset_glob, CR_FD_UNIXSK);

	struct cpt_inode_image *inode, *peer_inode;
	struct sock_struct *peer;
	int ret = -1;

	if (file->dumped || sk->dumped)
		return 0;

	if (!can_dump_unix_sk(sk)) {
		pr_err("Can't dump socket at @%li\n", obj_pos_of(sk));
		return -1;
	}

	inode = obj_lookup_img(CPT_OBJ_INODE, file->fi.cpt_inode);
	if (!inode) {
		pr_err("No inode @%li for file at @%li\n",
		       (long)file->fi.cpt_inode, obj_pos_of(file));
		return -1;
	}

	if (sk->si.cpt_peer != -1) {
		peer = sk_lookup_index(sk->si.cpt_peer);
		if (!peer) {
			pr_err("No peer with index %d found at @%li\n",
			       (int)sk->si.cpt_peer, obj_pos_of(file));
			return -1;
		}

		peer_inode = socket_inode(peer);
		if (!peer_inode) {
			pr_err("No inode for peer %d found at @%li\n",
			       (int)sk->si.cpt_peer, obj_pos_of(file));
			return -1;
		}
	} else {
		peer = NULL;
		peer_inode = NULL;
	}

	fill_fown(&fown, file);

	ue.name.len		= (size_t)sk->si.cpt_laddrlen - 2;
	ue.name.data		= (void *)&((char *)sk->si.cpt_laddr)[2];

	if (sk->si.cpt_laddrlen) {
		ue.file_perms	= &perms;
		perms.mode	= sk->si.cpt_i_mode;
		perms.uid	= sk->si.cpt_peer_uid;
		perms.gid	= sk->si.cpt_peer_gid;
	}

	ue.id			= obj_id_of(file);
	ue.ino			= inode->cpt_ino;
	ue.type			= sk->si.cpt_type;
	ue.state		= sk->si.cpt_state;

	ue.flags		= file->fi.cpt_flags;

	/* FIXME This is valid for TCP_LISTEN only */
	ue.backlog		= sk->si.cpt_max_ack_backlog;

	ue.peer			= peer_inode ? peer_inode->cpt_ino : 0;
	ue.fown			= &fown;
	ue.opts			= &skopts;
	ue.uflags		= 0;

	if (sk->si.cpt_shutdown != SK_SHUTDOWN__NONE) {
		ue.has_shutdown	= true;
		ue.shutdown	= sk->si.cpt_shutdown;
	}

	if (fill_socket_opts(ctx, sk, &skopts))
		return -1;

	/*
	 * FIXME No socket filters on cpt image
	 */

	ret = pb_write_one(fd, &ue, PB_UNIXSK);

	if (!ret) {
		file->dumped = true;
		sk->dumped = true;
	}

	return ret;
}

static int write_tcp(context_t *ctx,
		     struct file_struct *file,
		     struct sock_struct *sk)
{
	if (sk->si.cpt_state != TCP_ESTABLISHED)
		return 0;

	/*
	 * FIXME convert queue
	 */

	return 0;
}

static int write_inet_socket(context_t *ctx,
			     struct file_struct *file,
			     struct sock_struct *sk)
{
	InetSkEntry ie = INET_SK_ENTRY__INIT;
	SkOptsEntry skopts = SK_OPTS_ENTRY__INIT;
	FownEntry fown = FOWN_ENTRY__INIT;

	int fd = fdset_fd(ctx->fdset_glob, CR_FD_INETSK);

	struct cpt_inode_image *inode;
	void *src, *dst;
	int ret = -1;

	if (file->dumped)
		return 0;

	inode = obj_lookup_img(CPT_OBJ_INODE, file->fi.cpt_inode);
	if (!inode) {
		pr_err("No inode @%li for file at @%li\n",
		       (long)file->fi.cpt_inode, obj_pos_of(file));
		return -1;
	}

	fill_fown(&fown, file);

	ie.id		= obj_id_of(file);
	ie.ino		= inode->cpt_ino;
	ie.family	= sk->si.cpt_family;
	ie.proto	= sk->si.cpt_protocol;
	ie.type		= sk->si.cpt_type;
	ie.state	= sk->si.cpt_state;
	ie.src_port	= ntohs(sk->si.cpt_sport);
	ie.dst_port	= ntohs(sk->si.cpt_dport);

	/* FIXME This is valid for TCP_LISTEN only */
	ie.backlog	= sk->si.cpt_max_ack_backlog;
	ie.flags	= file->fi.cpt_flags;

	ie.fown		= &fown;
	ie.opts		= &skopts;

	if (fill_socket_opts(ctx, sk, &skopts))
		return -1;

	/*
	 * FIXME No socket filters on cpt image?
	 */

	if (ie.family == PF_INET6) {
		ie.n_src_addr = PB_ALEN_INET6;
		ie.n_dst_addr = PB_ALEN_INET6;

		ie.has_v6only = true;
		ie.v6only = sk->si.cpt_ipv6only6;
	} else if (ie.family == AF_INET) {
		ie.n_src_addr = PB_ALEN_INET;
		ie.n_dst_addr = PB_ALEN_INET;
	}

	src = ie.src_addr = xzalloc(pb_repeated_size(&ie, src_addr));
	dst = ie.dst_addr = xzalloc(pb_repeated_size(&ie, dst_addr));

	if (!ie.src_addr || !ie.dst_addr)
		goto err;

	if (ie.family == PF_INET6) {
		struct sockaddr_in6 *sin6;

		if (sk->si.cpt_laddrlen) {
			sin6 = (void *)sk->si.cpt_laddr;
			memcpy(ie.src_addr, &sin6->sin6_addr, pb_repeated_size(&ie, src_addr));
		}

		if (sk->si.cpt_raddrlen) {
			sin6 = (void *)sk->si.cpt_raddr;
			memcpy(ie.dst_addr, &sin6->sin6_addr, pb_repeated_size(&ie, dst_addr));
		}
	} else {
		struct sockaddr_in *sin;

		if (sk->si.cpt_laddrlen) {
			sin = (void *)sk->si.cpt_laddr;
			memcpy(ie.src_addr, &sin->sin_addr.s_addr, pb_repeated_size(&ie, src_addr));
		}

		if (sk->si.cpt_raddrlen) {
			sin = (void *)sk->si.cpt_raddr;
			memcpy(ie.dst_addr, &sin->sin_addr.s_addr, pb_repeated_size(&ie, dst_addr));
		}
	}

	ret = pb_write_one(fd, &ie, PB_INETSK);
	if (!ret) {
		if (sk->si.cpt_protocol == IPPROTO_TCP)
			ret = write_tcp(ctx, file, sk);
		if (!ret)
			file->dumped = true;
	}

err:
	xfree(src);
	xfree(dst);
	return ret;
}

static int write_netlink_socket(context_t *ctx,
				struct file_struct *file,
				struct sock_struct *sk)
{
	NetlinkSkEntry ne = NETLINK_SK_ENTRY__INIT;
	SkOptsEntry skopts = SK_OPTS_ENTRY__INIT;
	FownEntry fown = FOWN_ENTRY__INIT;

	int fd = fdset_fd(ctx->fdset_glob, CR_FD_NETLINKSK);

	struct cpt_inode_image *inode;
	int ret = -1;

	if (file->dumped)
		return 0;

	inode = obj_lookup_img(CPT_OBJ_INODE, file->fi.cpt_inode);
	if (!inode) {
		pr_err("No inode @%li for file at @%li\n",
		       (long)file->fi.cpt_inode, obj_pos_of(file));
		return -1;
	}

	fill_fown(&fown, file);

	ne.id		= obj_id_of(file);
	ne.ino		= inode->cpt_ino;
	ne.protocol	= sk->si.cpt_protocol;

	/*
	 * FIXME There are not all parameters present in
	 * 	 image, so that @portid, @groups, @dst_portid
	 *	 @dst_group are missing :(
	 */

	ne.fown		= &fown;
	ne.opts		= &skopts;

	if (fill_socket_opts(ctx, sk, &skopts))
		return -1;

	ret = pb_write_one(fd, &ne, PB_NETLINKSK);

	return ret;
}

int write_socket(context_t *ctx, struct file_struct *file)
{
	struct sock_struct *sk = sk_lookup_file(obj_of(file)->o_pos);
	int ret = -1;

	BUG_ON(!sk);

	switch (sk->si.cpt_family) {
	case PF_INET:
	case PF_INET6:
		ret = write_inet_socket(ctx, file, sk);
		break;
	case PF_UNIX:
		ret = write_unix_socket(ctx, file, sk);
		break;
	case PF_NETLINK:
		ret = write_netlink_socket(ctx, file, sk);
		break;
	default:
		pr_err("File at @%li with unsupported sock family %d\n",
		       (long)obj_of(file)->o_pos, (int)sk->si.cpt_family);
		break;
	}

	return ret;
}

void free_sockets(context_t *ctx)
{
	struct sock_struct *sk;

	while ((sk = obj_pop_unhash_to(CPT_OBJ_SOCKET)))
		obj_free_to(sk);
}

static void show_sock_addrs(struct sock_struct *sk)
{
	unsigned int i;
	char *c;

	if (sk->si.cpt_laddrlen) {
		pr_debug("\t\t\tlocal (%d)\n\t\t\t", sk->si.cpt_laddrlen);
		c = (char *)sk->si.cpt_laddr;
		for (i = 0; i < sk->si.cpt_laddrlen; i++, c++) {
			pr_debug("%2x:", (int)*c);
			if (i && (i % 8) == 0)
				pr_debug("\n\t\t\t");
		}
		if (sk->si.cpt_family == PF_UNIX) {
			pr_debug("\n\t\t\t --> ");
			c = (char *)sk->si.cpt_laddr;
			for (i = 0; i < sk->si.cpt_laddrlen; i++, c++)
				pr_debug("%c", isascii(*c) ? *c : ' ');
		}
		pr_debug("\n");
	}

	if (sk->si.cpt_raddrlen) {
		pr_debug("\t\t\tremote (%d)\n\t\t\t", sk->si.cpt_raddrlen);
		c = (char *)sk->si.cpt_raddr;
		for (i = 0; i < sk->si.cpt_raddrlen; i++, c++) {
			pr_debug("%2x:", (int)*c);
			if (i && (i % 8) == 0)
				pr_debug("\n\t\t\t");
		}
		if (sk->si.cpt_family == PF_UNIX) {
			pr_debug("\n\t\t\t --> ");
			c = (char *)sk->si.cpt_raddr;
			for (i = 0; i < sk->si.cpt_raddrlen; i++, c++)
				pr_debug("%c", isascii(*c) ? *c : ' ');
		}
		pr_debug("\n");
	}
}

static void show_sock_cont(context_t *ctx, struct sock_struct *sk)
{
	pr_debug("\t@%-8li file %8li parent %8d index %#x type %6d family %6d state %d\n"
		 "\t\tssflags %#lx sstate %#2x reuse %#2x zapped %#2x shutdown %#2x protocol %#2x\n"
		 "\t\tflags %#lx peer %#x socketpair %#2x sockflags %#2x cpt_bound_dev_if %#2x\n",
		 (long)obj_of(sk)->o_pos, (long)sk->si.cpt_file, sk->si.cpt_parent,
		 sk->si.cpt_index, (int)sk->si.cpt_type, (int)sk->si.cpt_family,
		 (int)sk->si.cpt_state, (long)sk->si.cpt_ssflags, sk->si.cpt_sstate,
		 sk->si.cpt_reuse, sk->si.cpt_zapped, sk->si.cpt_shutdown, sk->si.cpt_protocol,
		 (long)sk->si.cpt_flags, sk->si.cpt_peer, sk->si.cpt_socketpair,
		 sk->si.cpt_sockflags, sk->si.cpt_bound_dev_if);
	show_sock_addrs(sk);
}

int read_sockets(context_t *ctx)
{
	off_t start, end;

	pr_read_start("sockets\n");
	get_section_bounds(ctx, CPT_SECT_SOCKET, &start, &end);

	while (start < end) {
		struct sock_struct *sk;

		sk = obj_alloc_to(struct sock_struct, si);
		if (!sk)
			return -1;

		if (read_obj_cpt(ctx->fd, CPT_OBJ_SOCKET, &sk->si, start)) {
			obj_free_to(sk);
			pr_err("Can't read socket object at @%li\n", (long)start);
			return -1;
		}

		INIT_HLIST_NODE(&sk->hash);
		INIT_HLIST_NODE(&sk->index_hash);
		sk->dumped = false;

		hash_add(sock_hash, &sk->hash, sk->si.cpt_file);
		hash_add(sock_index_hash, &sk->index_hash, sk->si.cpt_index);

		obj_push_hash_to(sk, CPT_OBJ_SOCKET, start);
		start += sk->si.cpt_next;

		show_sock_cont(ctx, sk);
	}
	pr_read_end();

	return 0;
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

	pr_debug("\t@%-8li index %#8x flags %#8x mtu %#8x -> %s\n",
		 (long)obj_of(dev)->o_pos, dev->ni.cpt_index,
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
	pr_debug("\t@%-8li index %#8x family %#1x masklen %#1x "
		 "flags %#1x scope %#1x -> %s\n", (long)obj_of(ifa)->o_pos,
		 ifa->ii.cpt_index, (int)ifa->ii.cpt_family, (int)ifa->ii.cpt_masklen,
		 (int)ifa->ii.cpt_flags, (int)ifa->ii.cpt_scope, (char *)ifa->ii.cpt_label);
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
			pr_err("No net device with index %u at @%li\n",
			       ifa->ii.cpt_index, (long)start);
			obj_free_to(ifa);
			return -1;
		}

		INIT_LIST_HEAD(&ifa->list);
		obj_set_eos(ifa->ii.cpt_label);

		list_add_tail(&ifa->list, &ifaddr_list);

		start += ifa->ii.cpt_next;

		show_ifaddr_cont(ctx, ifa);
	}
	pr_read_end();

	return 0;
}
