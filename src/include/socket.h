#ifndef __CPT2_SOCKET_H__
#define __CPT2_SOCKET_H__

#include <stdbool.h>
#include <limits.h>

#include "cpt-image.h"
#include "context.h"
#include "types.h"
#include "files.h"
#include "list.h"

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

enum {
	TCPF_ESTABLISHED	= (1 <<  1),
	TCPF_SYN_SENT		= (1 <<  2),
	TCPF_SYN_RECV		= (1 <<  3),
	TCPF_FIN_WAIT1		= (1 <<  4),
	TCPF_FIN_WAIT2		= (1 <<  5),
	TCPF_TIME_WAIT		= (1 <<  6),
	TCPF_CLOSE		= (1 <<  7),
	TCPF_CLOSE_WAIT		= (1 <<  8),
	TCPF_LAST_ACK		= (1 <<  9),
	TCPF_LISTEN		= (1 << 10),
	TCPF_CLOSING		= (1 << 11)
};

#define	TCP_ECN_OK		1
#define	TCP_ECN_QUEUE_CWR	2
#define	TCP_ECN_DEMAND_CWR	4
#define	TCP_ECN_SEEN		8

#define TCPI_OPT_TIMESTAMPS	 1
#define TCPI_OPT_SACK		 2
#define TCPI_OPT_WSCALE		 4
#define TCPI_OPT_ECN		 8 /* ECN was negociated at TCP session init */
#define TCPI_OPT_ECN_SEEN	16 /* we received at least one packet with ECT */
#define TCPI_OPT_SYN_DATA	32 /* SYN-ACK acked data in SYN sent or rcvd */

#define TCP_NAGLE_OFF		1 /* Nagle's algo is disabled */
#define TCP_NAGLE_CORK		2 /* Socket is corked	    */
#define TCP_NAGLE_PUSH		4 /* Cork is overridden for already queued data */

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

extern const char *sock_proto_family(int family);

extern int read_sockets(context_t *ctx);
extern void free_sockets(context_t *ctx);
extern struct sock_struct *sk_lookup_file(u64 cpt_file);
extern int write_socket(context_t *ctx, struct file_struct *file);
extern int write_extern_unix(context_t *ctx);

static inline bool sock_flag(const struct sock_struct *sk, enum sock_flags flag)
{
	return (sk->si.cpt_flags & (1 << flag));
}

static inline bool before(u32 seq1, u32 seq2)
{
        return (s32)(seq1 - seq2) < 0;
}

static inline bool after(u32 seq2, u32 seq1)
{
	return before(seq1, seq2);
}

#endif /* __CPT2_SOCKET_H__ */
