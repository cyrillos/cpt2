#ifndef __CPT2_NET_H__
#define __CPT2_NET_H__

#include <stdbool.h>
#include <limits.h>

#include "cpt-image.h"
#include "context.h"
#include "types.h"
#include "files.h"
#include "list.h"

struct netdev_struct {
	struct list_head		list;
	struct hlist_node		hash;

	struct cpt_netdev_image		ni;
	struct cpt_hwaddr_image		hwi;
	struct cpt_netstats_image	nsi;

	int				utype;
	union {
		struct cpt_veth_image	vti;
		struct cpt_tuntap_image	tti;
		struct cpt_tunnel_image	tli;
		struct cpt_br_image	bri;
	} u;
};

struct ifaddr_struct {
	struct list_head		list;

	struct cpt_ifaddr_image		ii;
};

extern struct netdev_struct *netdev_lookup(u32 cpt_index);
extern int read_netdevs(context_t *ctx);
extern int write_netdevs(context_t *ctx);
extern void free_netdevs(context_t *ctx);

extern int read_ifaddr(context_t *ctx);
extern int write_ifaddr(context_t *ctx);
extern void free_ifaddr(context_t *ctx);
extern int write_routes(context_t *ctx);

#endif /* __CPT2_NET_H__ */
