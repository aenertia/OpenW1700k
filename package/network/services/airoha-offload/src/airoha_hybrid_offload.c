// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright: Joel Wirāmu Pauling <aenertia@aenertia.net>
//
// Artifact Name: airoha_hybrid_offload.c
// Purpose: XDP ingress observer/classifier for Airoha AN7581.
//          Parses packet headers, performs FIB and FDB lookups, prepends
//          routing metadata, and submits flow keys to a ring buffer for
//          the userspace sync daemon. Always returns XDP_PASS — this program
//          is an observer, not a filter. Conntrack lookup is deferred to
//          the daemon to avoid CO-RE/vmlinux.h dependency.
//
// See: ADR-001-ebpf-soft-hook.md

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* ---------- constants ---------- */

#define ETH_P_8021Q  0x8100
#define ETH_P_8021AD 0x88A8

#define AIROHA_META_MAGIC       0xA1B2C3D4
#define AIROHA_FLOW_OFFLOAD_MARK 0xAF00
#define AIROHA_OFFLOAD_HWNAT    0x01
#define AIROHA_OFFLOAD_WED      0x02

/* ---------- structures ---------- */

struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

/*
 * Flow key submitted to the daemon via ring buffer.
 * The daemon performs conntrack lookup and tracks state internally.
 */
struct flow_key {
	__u32  src_ip[4];
	__u32  dst_ip[4];
	__be16 src_port;
	__be16 dst_port;
	__be16 l3_proto;
	__u8   l4_proto;
	__u8   padding;
};

/*
 * Ring buffer event — flow key plus ingress/egress context
 * so the daemon can make offload decisions without another lookup.
 */
struct flow_event {
	struct flow_key key;
	__u32  ingress_ifindex;
	__u32  egress_ifindex;
	__u8   smac[6];
	__u8   dmac[6];
	__u8   offload_cap;     /* from iface_offload_map */
	__u8   is_bridge_fwd;   /* 1 if resolved via FDB, 0 if FIB */
	__u16  pkt_len;
	__u8   dscp;
	__u8   _pad;
};

/*
 * Metadata prepended to the packet via bpf_xdp_adjust_meta().
 * Available to downstream TC/XDP programs via data_meta.
 */
struct airoha_meta {
	__u32  magic;
	__u32  mark;
	__u32  egress_ifindex;
	__be32 src_ip[4];
	__be32 dst_ip[4];
	__be16 src_port;
	__be16 dst_port;
	__u8   smac[6];
	__u8   dmac[6];
	__be16 l3_proto;
	__u8   l4_proto;
	__u8   offload_flags;
};

/* ---------- FDB key for bridge forwarding lookup ---------- */

struct fdb_key {
	__u8   mac[6];
	__u16  padding;
	__u32  bridge_ifindex;
};

/* ---------- BPF maps ---------- */

/*
 * Interface capability map.  Populated by daemon via netlink listener.
 * Key: ifindex, Value: offload capability (0=none, 1=WED, 2=HWNAT).
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u8);
} iface_offload_map SEC(".maps");

/*
 * MAC FDB map.  Populated by daemon from RTM_NEWNEIGH netlink events.
 * Key: (dst_mac, bridge_ifindex), Value: egress port ifindex.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct fdb_key);
	__type(value, __u32);
} mac_fdb_map SEC(".maps");

/*
 * Port-to-bridge map.  Populated by daemon from RTM_NEWLINK (IFLA_MASTER).
 * Key: port ifindex, Value: bridge ifindex.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u32);
} port_to_bridge_map SEC(".maps");

/*
 * Ring buffer for flow events.  The XDP program submits flow keys here;
 * the daemon consumes them, performs conntrack lookup, and decides whether
 * to track the flow for hardware stats synchronisation.
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} flow_event_rb SEC(".maps");

/*
 * DSCP classification map. Populated by daemon at startup.
 * Key: DSCP value (0-63, 6-bit), Value: classification mark (0xAF01..0xAF04).
 * If a DSCP is not in the map, default mark 0xAF02 (normal, offloadable) is used.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u8);
	__type(value, __u32);
} dscp_class_map SEC(".maps");

/* ---------- helpers ---------- */

static __always_inline int parse_l4(void *l4_hdr, void *data_end,
				    __u8 l4_proto,
				    __be16 *src_port, __be16 *dst_port)
{
	if (l4_proto == IPPROTO_TCP) {
		struct tcphdr *tcp = l4_hdr;
		if ((void *)(tcp + 1) > data_end)
			return -1;
		*src_port = tcp->source;
		*dst_port = tcp->dest;
		return 0;
	}
	if (l4_proto == IPPROTO_UDP) {
		struct udphdr *udp = l4_hdr;
		if ((void *)(udp + 1) > data_end)
			return -1;
		*src_port = udp->source;
		*dst_port = udp->dest;
		return 0;
	}
	return -1; /* unsupported L4 — skip */
}

/* ---------- XDP program ---------- */

SEC("xdp")
int airoha_classify(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	/* --- L2 parse --- */
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	__be16 h_proto   = eth->h_proto;
	int    hdr_offset = sizeof(*eth);

	/* Strip up to 2 VLAN tags (802.1Q / 802.1ad) */
	#pragma unroll
	for (int i = 0; i < 2; i++) {
		if (h_proto != bpf_htons(ETH_P_8021Q) &&
		    h_proto != bpf_htons(ETH_P_8021AD))
			break;
		struct vlan_hdr *vhdr = data + hdr_offset;
		if ((void *)(vhdr + 1) > data_end)
			return XDP_PASS;
		h_proto     = vhdr->h_vlan_encapsulated_proto;
		hdr_offset += sizeof(struct vlan_hdr);
	}

	/* Only process IPv4 / IPv6 */
	if (h_proto != bpf_htons(ETH_P_IP) && h_proto != bpf_htons(ETH_P_IPV6))
		return XDP_PASS;

	/* --- L3 parse --- */
	__be16 src_port = 0, dst_port = 0;
	__u8   l4_proto = 0;
	__u8   dscp = 0;
	__u32  src_ip[4] = {};
	__u32  dst_ip[4] = {};
	void  *l4_hdr;
	__u16  pkt_len = 0;

	if (h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = data + hdr_offset;
		if ((void *)(ip + 1) > data_end)
			return XDP_PASS;
		/* Skip fragments */
		if (ip->frag_off & bpf_htons(0x3FFF))
			return XDP_PASS;

		l4_proto  = ip->protocol;
		l4_hdr    = (void *)ip + (ip->ihl * 4);
		pkt_len   = bpf_ntohs(ip->tot_len);
		src_ip[0] = ip->saddr;
		dst_ip[0] = ip->daddr;
		dscp = (ip->tos >> 2) & 0x3f;
	} else {
		struct ipv6hdr *ip6 = data + hdr_offset;
		if ((void *)(ip6 + 1) > data_end)
			return XDP_PASS;
		/* Skip extension headers — only handle direct next header */
		if (ip6->nexthdr == IPPROTO_FRAGMENT)
			return XDP_PASS;

		l4_proto = ip6->nexthdr;
		l4_hdr   = (void *)(ip6 + 1);
		pkt_len  = bpf_ntohs(ip6->payload_len) + sizeof(*ip6);
		__builtin_memcpy(src_ip, &ip6->saddr, 16);
		__builtin_memcpy(dst_ip, &ip6->daddr, 16);
		dscp = (bpf_ntohl(*(__u32 *)ip6) >> 22) & 0x3f;
	}

	/* --- L4 parse --- */
	if (parse_l4(l4_hdr, data_end, l4_proto, &src_port, &dst_port) < 0)
		return XDP_PASS;

	/* Skip tiny packets (e.g. keepalives) — not worth tracking */
	if (pkt_len < 128)
		return XDP_PASS;

	/* --- FDB lookup for bridged traffic --- */
	__u32 egress_ifindex = 0;
	__u8  is_bridge_fwd  = 0;
	__u8  smac[6], dmac[6];

	__u32 ingress = ctx->ingress_ifindex;
	__u32 *bridge_ifindex = bpf_map_lookup_elem(&port_to_bridge_map,
						    &ingress);
	if (bridge_ifindex) {
		struct fdb_key fkey = {};
		__builtin_memcpy(fkey.mac, eth->h_dest, 6);
		fkey.bridge_ifindex = *bridge_ifindex;

		__u32 *fdb_port = bpf_map_lookup_elem(&mac_fdb_map, &fkey);
		if (fdb_port && *fdb_port != 0) {
			egress_ifindex = *fdb_port;
			is_bridge_fwd  = 1;
			__builtin_memcpy(smac, eth->h_source, 6);
			__builtin_memcpy(dmac, eth->h_dest, 6);
		}
	}

	/* --- FIB lookup for routed traffic --- */
	if (egress_ifindex == 0) {
		struct bpf_fib_lookup fib = {};

		if (h_proto == bpf_htons(ETH_P_IP)) {
			fib.family   = AF_INET;
			fib.ipv4_src = src_ip[0];
			fib.ipv4_dst = dst_ip[0];
		} else {
			fib.family = AF_INET6;
			__builtin_memcpy(fib.ipv6_src, src_ip, 16);
			__builtin_memcpy(fib.ipv6_dst, dst_ip, 16);
		}
		fib.ifindex = ingress;

		int rc = bpf_fib_lookup(ctx, &fib, sizeof(fib), 0);
		if (rc != BPF_FIB_LKUP_RET_SUCCESS)
			return XDP_PASS;

		egress_ifindex = fib.ifindex;
		__builtin_memcpy(smac, fib.smac, 6);
		__builtin_memcpy(dmac, fib.dmac, 6);
	}

	/* --- Check egress interface offload capability --- */
	__u8 *offload_cap = bpf_map_lookup_elem(&iface_offload_map,
						&egress_ifindex);
	if (!offload_cap || *offload_cap == 0)
		return XDP_PASS;

	/* --- Prepend XDP metadata --- */
	if (bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct airoha_meta)))
		return XDP_PASS;

	/* Re-derive pointers after adjust_meta */
	data     = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	struct airoha_meta *meta = (void *)(long)ctx->data_meta;

	if ((void *)(meta + 1) > data)
		return XDP_PASS;

	meta->magic          = AIROHA_META_MAGIC;
	__u32 *class_mark = bpf_map_lookup_elem(&dscp_class_map, &dscp);
	meta->mark = class_mark ? *class_mark : 0xAF02; /* default: normal, offloadable */
	meta->egress_ifindex = egress_ifindex;
	__builtin_memcpy(meta->src_ip, src_ip, sizeof(meta->src_ip));
	__builtin_memcpy(meta->dst_ip, dst_ip, sizeof(meta->dst_ip));
	meta->src_port       = src_port;
	meta->dst_port       = dst_port;
	__builtin_memcpy(meta->smac, smac, 6);
	__builtin_memcpy(meta->dmac, dmac, 6);
	meta->l3_proto       = h_proto;
	meta->l4_proto       = l4_proto;

	if (*offload_cap == 1)
		meta->offload_flags = AIROHA_OFFLOAD_WED;
	else if (*offload_cap == 2)
		meta->offload_flags = AIROHA_OFFLOAD_HWNAT;
	else
		meta->offload_flags = 0;

	/* --- Submit flow key to ring buffer for daemon --- */
	struct flow_event *evt;
	evt = bpf_ringbuf_reserve(&flow_event_rb, sizeof(*evt), 0);
	if (evt) {
		__builtin_memcpy(&evt->key.src_ip, src_ip, sizeof(src_ip));
		__builtin_memcpy(&evt->key.dst_ip, dst_ip, sizeof(dst_ip));
		evt->key.src_port  = src_port;
		evt->key.dst_port  = dst_port;
		evt->key.l3_proto  = h_proto;
		evt->key.l4_proto  = l4_proto;
		evt->key.padding   = 0;

		evt->ingress_ifindex = ingress;
		evt->egress_ifindex  = egress_ifindex;
		__builtin_memcpy(evt->smac, smac, 6);
		__builtin_memcpy(evt->dmac, dmac, 6);
		evt->offload_cap     = *offload_cap;
		evt->is_bridge_fwd   = is_bridge_fwd;
		evt->pkt_len         = pkt_len;
		evt->dscp            = dscp;
		evt->_pad            = 0;

		bpf_ringbuf_submit(evt, 0);
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
