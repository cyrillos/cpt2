#ifndef __CPT2_NET_H__
#define __CPT2_NET_H__

#include <stdbool.h>
#include <limits.h>

#include "cpt-image.h"
#include "context.h"
#include "types.h"
#include "files.h"
#include "list.h"

struct task_struct;

#define	MAX_SCHEDULE_TIMEOUT	LONG_MAX

#define SOCK_ASYNC_NOSPACE		0
#define SOCK_ASYNC_WAITDATA		1
#define SOCK_NOSPACE			2
#define SOCK_PASSCRED			3
#define SOCK_PASSSEC			4
#define SOCK_EXTERNALLY_ALLOCATED	5

enum sock_flags {
	SOCK_DEAD,
	SOCK_DONE,
	SOCK_URGINLINE,
	SOCK_KEEPOPEN,
	SOCK_LINGER,
	SOCK_DESTROY,
	SOCK_BROADCAST,
	SOCK_TIMESTAMP,
	SOCK_ZAPPED,
	SOCK_USE_WRITE_QUEUE,
	SOCK_DBG,
	SOCK_RCVTSTAMP,
	SOCK_RCVTSTAMPNS,
	SOCK_LOCALROUTE,
	SOCK_QUEUE_SHRUNK,
	SOCK_MEMALLOC,
	SOCK_TIMESTAMPING_TX_HARDWARE,
	SOCK_TIMESTAMPING_TX_SOFTWARE,
	SOCK_TIMESTAMPING_RX_HARDWARE,
	SOCK_TIMESTAMPING_RX_SOFTWARE,
	SOCK_TIMESTAMPING_SOFTWARE,
	SOCK_TIMESTAMPING_RAW_HARDWARE,
	SOCK_TIMESTAMPING_SYS_HARDWARE,
	SOCK_FASYNC,
	SOCK_RXQ_OVFL,
	SOCK_ZEROCOPY,
	SOCK_WIFI_STATUS,
	SOCK_NOFCS,
	SOCK_FILTER_LOCKED,
};

#define INVALID_INDEX	-1
#define USK_EXTERN	(1 << 0)

struct sock_aux_pos {
	/*
	 * Attributes.
	 */
	off_t				off_skfilter;
	off_t				off_mcaddr;

	/*
	 * Read queue.
	 */
	off_t				off_rqueue;

	/*
	 * Write queue.
	 */
	off_t				off_wqueue;
	off_t				off_ofoqueue;

	/*
	 * Synwaits.
	 */
	off_t				off_synwait_queue;
};

struct sock_struct {
	struct hlist_node		hash;
	struct hlist_node		index_hash;
	struct list_head		list;
	bool				dumped;
	struct sock_aux_pos		aux_pos;

	struct cpt_sock_image		si;
};

struct netdev_struct {
	struct list_head		list;
	struct hlist_node		hash;

	struct cpt_netdev_image		ni;
	struct cpt_hwaddr_image		hwi;
};

struct ifaddr_struct {
	struct list_head		list;

	struct cpt_ifaddr_image		ii;
};

extern int read_sockets(context_t *ctx);
extern void free_sockets(context_t *ctx);
extern struct sock_struct *sk_lookup_file(u64 cpt_file);
extern int write_extern_unix(context_t *ctx);

extern int read_netdevs(context_t *ctx);
extern int write_netdevs(context_t *ctx);
extern void free_netdevs(context_t *ctx);

extern int write_socket(context_t *ctx, struct file_struct *file);

extern int read_ifaddr(context_t *ctx);
extern int write_ifaddr(context_t *ctx);
extern void free_ifaddr(context_t *ctx);
extern int write_routes(context_t *ctx);

#endif /* __CPT2_NET_H__ */
