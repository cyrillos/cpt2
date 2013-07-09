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
#include <linux/filter.h>

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
#include "protobuf/sk-unix.pb-c.h"
#include "protobuf/sk-inet.pb-c.h"
#include "protobuf/sk-netlink.pb-c.h"

static const char *proto_families[] = {
	[PF_UNIX]		= "UNIX",
	[PF_INET]		= "INET",
	[PF_INET6]		= "INET6",
	[PF_NETLINK]		= "NETLINK",
	[PF_PACKET]		= "PACKET",
};

static const char *sock_states[] = {
	[TCP_ESTABLISHED]	= "ESTABLISHED",
	[TCP_SYN_SENT]		= "SYN-SENT",
	[TCP_SYN_RECV]		= "SYN-RECV",
	[TCP_FIN_WAIT1]		= "FIN-WAIT1",
	[TCP_FIN_WAIT2]		= "FIN-WAIT2",
	[TCP_TIME_WAIT]		= "TIME-WAIT",
	[TCP_CLOSE]		= "CLOSE",
	[TCP_CLOSE_WAIT]	= "CLOSE-WAIT",
	[TCP_LAST_ACK]		= "LAST-ACK",
	[TCP_LISTEN]		= "LISTEN",
	[TCP_CLOSING]		= "CLOSING",
};

static const char *sock_types[] = {
	[SOCK_STREAM]		= "STREAM",
	[SOCK_DGRAM]		= "DGRAM",
	[SOCK_RAW]		= "RAW",
	[SOCK_RDM]		= "RDM",
	[SOCK_SEQPACKET]	= "SEQPACKET",
	[SOCK_DCCP]		= "DCCP",
	[SOCK_PACKET]		= "PACKET",
};

#define NET_HASH_BITS		10
static DEFINE_HASHTABLE(sock_hash, NET_HASH_BITS);
static DEFINE_HASHTABLE(sock_index_hash, NET_HASH_BITS);

static LIST_HEAD(unix_sock_list);

#define PB_ALEN_INET	1
#define PB_ALEN_INET6	4

static void show_sock_cont(context_t *ctx, struct sock_struct *sk);

const char *sock_proto_family(int family)
{
	if (family < (int)ARRAY_SIZE(proto_families))
		return proto_families[family];
	return NULL;
}

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

/* Caller must always xfree skopts->so_filter */
static int fill_socket_filter(context_t *ctx, const struct sock_struct *sk, SkOptsEntry *skopts)
{
	const struct sock_aux_pos *aux = &sk->aux_pos;
	struct sock_filter *filter;
	struct cpt_obj_bits v;
	unsigned int len, i;

	if (!aux->off_skfilter)
		return 0;

	if (read_obj_cpt(ctx->fd, CPT_OBJ_SKFILTER, &v, aux->off_skfilter)) {
		pr_err("Failed reading socket filter at @%li\n", aux->off_skfilter);
		return -1;
	}

	len = v.cpt_size / sizeof(struct sock_filter);
	if (len) {
		/*
		 * We will need to encode filter bytestream
		 * so allocate enough memory for both read and
		 * encode buffers, the caller is to free this
		 * slab later.
		 */
		skopts->so_filter = xmalloc(len * sizeof(*skopts->so_filter) + v.cpt_size);
		if (!skopts->so_filter)
			goto err;
		filter = (void *)((char *)skopts->so_filter + len * sizeof(*skopts->so_filter));
		skopts->n_so_filter = len;

		if (read_data(ctx->fd, filter, v.cpt_size, false)) {
			pr_err("Failed reading socket filter at @%li\n", aux->off_skfilter);
			goto err;
		}

		for (i = 0; i < v.cpt_size; i++) {
			skopts->so_filter[i] =
				((u64)filter[i].code	<< 48) |
				((u64)filter[i].jt	<< 40) |
				((u64)filter[i].jf	<< 32) |
				((u64)filter[i].k	<<  0);
		}
	}

	return 0;

err:
	xfree(skopts->so_filter);
	skopts->n_so_filter = 0;
	return -1;
}

static int fill_socket_opts(context_t *ctx, const struct sock_struct *sk, SkOptsEntry *skopts)
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

	skopts->has_reuseaddr = true;
	skopts->reuseaddr = sk->si.cpt_reuse ? true : false;

	skopts->has_so_passcred = true;
	skopts->so_passcred = !!(sk->si.cpt_ssflags & (1 << SOCK_PASSCRED));

	skopts->has_so_passsec = true;
	skopts->so_passsec = !!(sk->si.cpt_ssflags & (1 << SOCK_PASSSEC));

	skopts->has_so_dontroute = true;
	skopts->so_dontroute = !!(sk->si.cpt_flags & (1 << SOCK_LOCALROUTE));

	skopts->has_so_no_check = true;
	skopts->so_no_check = sk->si.cpt_no_check;

	if (sk->si.cpt_bound_dev_if) {
		struct netdev_struct *dev = netdev_lookup(sk->si.cpt_bound_dev_if);
		if (!dev) {
			pr_err("No net device with index %#x found\n",
				sk->si.cpt_bound_dev_if);
			return -1;
		}

		skopts->so_bound_dev = (char *)dev->ni.cpt_name;
	}

	return fill_socket_filter(ctx, sk, skopts);
}

int write_extern_unix(context_t *ctx)
{
	int fd = fdset_fd(ctx->fdset_glob, CR_FD_UNIXSK);
	SkOptsEntry skopts = SK_OPTS_ENTRY__INIT;
	FownEntry fown = FOWN_ENTRY__INIT;
	struct sock_struct *sk;

	list_for_each_entry(sk, &unix_sock_list, list) {
		UnixSkEntry ue = UNIX_SK_ENTRY__INIT;

		if (sk->si.cpt_type != SOCK_DGRAM) {
			pr_err("Can't dump half of stream unix connection\n");
			show_sock_cont(ctx, sk);
			return -1;
		}

		ue.name.len		= (size_t)sk->si.cpt_laddrlen - 2;
		ue.name.data		= (void *)&((char *)sk->si.cpt_laddr)[2];

		ue.id			= obj_id_of(sk);
		ue.ino			= obj_id_of(sk);
		ue.type			= SOCK_DGRAM;
		ue.state		= TCP_LISTEN;
		ue.uflags		= USK_EXTERN;
		ue.peer			= 0;
		ue.fown			= &fown;
		ue.opts			= &skopts;

		if (pb_write_one(fd, &ue, PB_UNIXSK))
			return -1;
	}

	return 0;
}

static int write_unix_socket(context_t *ctx, struct file_struct *file, struct sock_struct *sk)
{
	FilePermsEntry perms = FILE_PERMS_ENTRY__INIT;
	SkOptsEntry skopts = SK_OPTS_ENTRY__INIT;
	UnixSkEntry ue = UNIX_SK_ENTRY__INIT;
	FownEntry fown = FOWN_ENTRY__INIT;

	int fd = fdset_fd(ctx->fdset_glob, CR_FD_UNIXSK);

	struct sock_struct *peer;
	int ret = -1;

	if (file->dumped || sk->dumped)
		return 0;

	if (!can_dump_unix_sk(sk)) {
		pr_err("Can't dump socket at @%li\n", obj_pos_of(sk));
		return -1;
	}

	if (sk->si.cpt_peer != INVALID_INDEX) {
		peer = sk_lookup_index(sk->si.cpt_peer);
		if (!peer) {
			pr_err("No peer with index %#x found at @%li\n",
			       (int)sk->si.cpt_peer, obj_pos_of(file));
			return -1;
		}

		/*
		 * Find appropriate ino if it's incoming connection.
		 */
		if (peer->si.cpt_file == INVALID_INDEX &&
		    peer->si.cpt_parent != INVALID_INDEX) {

			/*
			 * It's not external socket.
			 */
			if (!list_empty(&peer->list))
				list_del_init(&peer->list);

			peer = sk_lookup_index(peer->si.cpt_parent);
			if (!peer) {
				pr_err("No icon peer with index %#x found at @%li\n",
				       (int)sk->si.cpt_parent, obj_pos_of(file));
				return -1;
			}
		}
	} else
		peer = NULL;

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
	ue.ino			= obj_id_of(sk);
	ue.type			= sk->si.cpt_type;
	ue.state		= sk->si.cpt_state;

	ue.flags		= file->fi.cpt_flags;

	/* FIXME This is valid for TCP_LISTEN only */
	ue.backlog		= sk->si.cpt_max_ack_backlog;

	ue.peer			= peer ? obj_id_of(peer) : 0;
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
		list_del_init(&sk->list);
	}

	xfree(skopts.so_filter);
	return ret;
}

static int write_tcp(context_t *ctx, struct file_struct *file, struct sock_struct *sk)
{
	if (sk->si.cpt_state != TCP_ESTABLISHED)
		return 0;

	/*
	 * FIXME convert queue
	 */

	return 0;
}

static int write_inet_socket(context_t *ctx, struct file_struct *file, struct sock_struct *sk)
{
	SkOptsEntry skopts = SK_OPTS_ENTRY__INIT;
	InetSkEntry ie = INET_SK_ENTRY__INIT;
	FownEntry fown = FOWN_ENTRY__INIT;

	int fd = fdset_fd(ctx->fdset_glob, CR_FD_INETSK);

	void *src, *dst;
	int ret = -1;

	if (file->dumped)
		return 0;

	fill_fown(&fown, file);

	ie.id		= obj_id_of(file);
	ie.ino		= obj_id_of(sk);
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
	int ret = -1;

	if (file->dumped)
		return 0;

	fill_fown(&fown, file);

	ne.id		= obj_id_of(file);
	ne.ino		= obj_id_of(sk);
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
		       obj_pos_of(file), (int)sk->si.cpt_family);
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

static int sock_read_aux_pos(context_t *ctx, struct sock_struct *sk)
{
	struct sock_aux_pos *aux = &sk->aux_pos;
	union {
		struct cpt_object_hdr	h;
		struct cpt_skb_image	skb;
	} u;
	off_t start;

	for (start = obj_pos_of(sk) + sk->si.cpt_hdrlen;
	     start < obj_pos_of(sk) + sk->si.cpt_next;
	     start += u.h.cpt_next) {

		if (read_obj_hdr(ctx->fd, &u.h, start)) {
			pr_err("Can't read socket data header at @%li\n", (long)start);
			return -1;
		}

		switch (u.h.cpt_object) {
		case CPT_OBJ_SKFILTER:
			if (!aux->off_skfilter)
				aux->off_skfilter = start;
			break;
		case CPT_OBJ_SOCK_MCADDR:
			if (!aux->off_mcaddr)
				aux->off_mcaddr = start;
			break;
		case CPT_OBJ_SKB:
			if (read_obj_cont_until(ctx->fd, &u.skb, cpt_stamp)) {
				pr_err("Can't read skb at @%li\n", (long)start);
				return -1;
			}
			switch (u.skb.cpt_queue) {
			case CPT_SKB_RQ:
				if (!aux->off_rqueue)
					aux->off_rqueue = start;
				break;
			case CPT_SKB_WQ:
				if (!aux->off_wqueue)
					aux->off_wqueue = start;
				break;
			case CPT_SKB_OFOQ:
				if (!aux->off_ofoqueue)
					aux->off_ofoqueue = start;
				break;
			}
			break;
		case CPT_OBJ_OPENREQ:
			if (!aux->off_synwait_queue)
				aux->off_synwait_queue = start;
			break;
		default:
			goto unknown_obj;
		}
	}

	pr_debug("\t\t\toffs: @%-10li @%-10li @%-10li\n"
		 "\t\t\t      @%-10li @%-10li @%-10li\n",
		 (long)aux->off_skfilter, (long)aux->off_mcaddr, (long)aux->off_rqueue,
		 (long)aux->off_wqueue, (long)aux->off_ofoqueue, (long)aux->off_synwait_queue);
	return 0;

unknown_obj:
	pr_err("Unexpected object %d/%d at @%li\n",
	       u.h.cpt_object, u.h.cpt_content, (long)start);
	return -1;
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
	pr_debug("\t@%-10li file @%-10li parent %8d index %#x type %6d family %6d state %d\n"
		 "\t\tssflags %#lx sstate %#2x reuse %#2x zapped %#2x shutdown %#2x protocol %#2x\n"
		 "\t\tflags %#lx peer %#x socketpair %#2x sockflags %#2x cpt_bound_dev_if %#2x\n",
		 obj_pos_of(sk), (long)sk->si.cpt_file, sk->si.cpt_parent,
		 sk->si.cpt_index, (int)sk->si.cpt_type, (int)sk->si.cpt_family,
		 (int)sk->si.cpt_state, (long)sk->si.cpt_ssflags, sk->si.cpt_sstate,
		 sk->si.cpt_reuse, sk->si.cpt_zapped, sk->si.cpt_shutdown, sk->si.cpt_protocol,
		 (long)sk->si.cpt_flags, sk->si.cpt_peer, sk->si.cpt_socketpair,
		 sk->si.cpt_sockflags, sk->si.cpt_bound_dev_if);

	pr_debug("\t\t\ttype %12s family %12s state %12s ino %#x\n",
		 sk->si.cpt_type < ARRAY_SIZE(sock_types) ? sock_types[sk->si.cpt_type] : "UNK",
		 sk->si.cpt_family < ARRAY_SIZE(proto_families) ? proto_families[sk->si.cpt_family] : "UNK",
		 sk->si.cpt_state < ARRAY_SIZE(sock_states) ? sock_states[sk->si.cpt_state] : "UNK",
		 obj_id_of(sk));

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
		INIT_LIST_HEAD(&sk->list);
		sk->dumped = false;

		hash_add(sock_hash, &sk->hash, sk->si.cpt_file);

		if (sk->si.cpt_index != INVALID_INDEX)
			hash_add(sock_index_hash, &sk->index_hash, sk->si.cpt_index);

		/*
		 * Collect unix sockets into additional list, we will need
		 * this for external unix connections handling.
		 */
		if (sk->si.cpt_family == PF_UNIX)
			list_add(&sk->list, &unix_sock_list);

		obj_push_hash_to(sk, CPT_OBJ_SOCKET, start);
		start += sk->si.cpt_next;

		show_sock_cont(ctx, sk);

		if (sock_read_aux_pos(ctx, sk)) {
			pr_err("Failed read socket aux positions at @%li\n", (long)start);
			return -1;
		}
	}
	pr_read_end();

	return 0;
}
