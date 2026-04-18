// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright: Joel Wirāmu Pauling <aenertia@aenertia.net>
//
// Artifact Name: airoha_dsa_classify.c
// Purpose: TC-BPF ingress classifier for MT7530 DSA user ports (lan3, lan4).
//          Mirrors the XDP classifier's DSCP→mark and ring-buffer-reporting
//          logic, but operates on struct __sk_buff (not xdp_md).
//
//          The MTK DSA subsystem strips the 4-byte special tag before the skb
//          reaches TC ingress on user ports; the tag-skip logic is kept as a
//          defensive measure for configurations where the tag may still be
//          present (e.g. when TC is applied to the conduit interface).
//
//          Always returns TC_ACT_OK — this program is a classifier, not a
//          filter. It never drops packets.
//
//          BPF maps are reused from the XDP program's pinned paths via the
//          iproute2 "map name <X> pinned <path>" syntax at load time.
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

/* TC action codes (from linux/pkt_cls.h — not always available in BPF includes) */
#define TC_ACT_OK   0
#define TC_ACT_SHOT 2

#define ETH_P_8021Q  0x8100
#define ETH_P_8021AD 0x88A8

/*
 * MTK DSA special tag: 4 bytes prepended to (or inserted within) the
 * Ethernet frame by the MT7530 switch.  When present, byte 0 is 0x80
 * and byte 1 is 0x00.
 */
#define MTK_DSA_TAG_BYTE0 0x80
#define MTK_DSA_TAG_BYTE1 0x00
#define MTK_DSA_TAG_LEN   4

/* Skip tiny packets — not worth classifying (keepalives, ICMP, ARP) */
#define MIN_PKT_LEN 128

/* ---------- structures ---------- */

struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

/*
 * Flow key — must match airoha_hybrid_offload.c exactly so the daemon
 * can correlate events from both XDP and TC paths.
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
 * Ring buffer event — must match airoha_hybrid_offload.c exactly.
 * egress_ifindex is 0 for TC-path events (no FIB/FDB lookup performed).
 */
struct flow_event {
	struct flow_key key;
	__u32  ingress_ifindex;
	__u32  egress_ifindex;
	__u8   smac[6];
	__u8   dmac[6];
	__u8   offload_cap;     /* 0 for TC path — unknown without FIB */
	__u8   is_bridge_fwd;   /* 0 for TC path — unknown without FDB */
	__u16  pkt_len;
	__u8   dscp;
	__u8   _pad;
};

/* ---------- BPF maps ---------- */

/*
 * Ring buffer for flow events.  Shared with the XDP program.
 * The iproute2 loader reuses the XDP-pinned FD via:
 *   tc filter add ... map name flow_event_rb pinned /sys/fs/bpf/flow_event_rb
 * Definition must match airoha_hybrid_offload.c (same type, max_entries).
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} flow_event_rb SEC(".maps");

/*
 * DSCP classification map.  Populated by daemon at startup.
 * Key: DSCP value (0-63), Value: mark (0xAF01..0xAF04).
 * Shared with XDP program via:
 *   tc filter add ... map name dscp_class_map pinned /sys/fs/bpf/dscp_class_map
 * Definition must match airoha_hybrid_offload.c exactly.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u8);
	__type(value, __u32);
} dscp_class_map SEC(".maps");

/* ---------- TC-BPF classifier ---------- */

SEC("tc")
int airoha_dsa_classify(struct __sk_buff *skb)
{
	__u32 offset = 0;

	/*
	 * --- MTK DSA tag detection ---
	 * The MT7530 special tag has 0x80 at byte 0 and 0x00 at byte 1.
	 * If present, skip 4 bytes to reach the real Ethernet header.
	 * In normal DSA user-port operation the kernel strips this before TC,
	 * but guard defensively.
	 */
	__u8 tag_b0 = 0, tag_b1 = 0;
	if (bpf_skb_load_bytes(skb, 0, &tag_b0, 1) < 0)
		return TC_ACT_OK;
	if (tag_b0 == MTK_DSA_TAG_BYTE0) {
		if (bpf_skb_load_bytes(skb, 1, &tag_b1, 1) < 0)
			return TC_ACT_OK;
		if (tag_b1 == MTK_DSA_TAG_BYTE1)
			offset = MTK_DSA_TAG_LEN;
	}

	/* --- L2 parse: Ethernet header --- */
	struct ethhdr eth;
	if (bpf_skb_load_bytes(skb, offset, &eth, sizeof(eth)) < 0)
		return TC_ACT_OK;
	offset += sizeof(eth);

	__be16 h_proto = eth.h_proto;

	/* Strip up to 2 VLAN tags (802.1Q / 802.1ad) */
	#pragma unroll
	for (int i = 0; i < 2; i++) {
		if (h_proto != bpf_htons(ETH_P_8021Q) &&
		    h_proto != bpf_htons(ETH_P_8021AD))
			break;
		struct vlan_hdr vhdr;
		if (bpf_skb_load_bytes(skb, offset, &vhdr, sizeof(vhdr)) < 0)
			return TC_ACT_OK;
		h_proto = vhdr.h_vlan_encapsulated_proto;
		offset += sizeof(vhdr);
	}

	/* Only classify IPv4 and IPv6 */
	if (h_proto != bpf_htons(ETH_P_IP) && h_proto != bpf_htons(ETH_P_IPV6))
		return TC_ACT_OK;

	/* --- L3 parse --- */
	__be16 src_port = 0, dst_port = 0;
	__u8   l4_proto = 0;
	__u8   dscp     = 0;
	__u32  src_ip[4] = {};
	__u32  dst_ip[4] = {};
	__u32  l4_offset = 0;
	__u16  pkt_len   = 0;

	if (h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr ip;
		if (bpf_skb_load_bytes(skb, offset, &ip, sizeof(ip)) < 0)
			return TC_ACT_OK;

		/* Skip fragments — no reassembly in BPF */
		if (ip.frag_off & bpf_htons(0x3FFF))
			return TC_ACT_OK;

		/* Guard against malformed IHL */
		__u32 ihl = ip.ihl;
		if (ihl < 5)
			return TC_ACT_OK;

		l4_proto  = ip.protocol;
		l4_offset = offset + (ihl * 4);
		pkt_len   = bpf_ntohs(ip.tot_len);
		src_ip[0] = ip.saddr;
		dst_ip[0] = ip.daddr;
		dscp = (ip.tos >> 2) & 0x3f;

	} else { /* ETH_P_IPV6 */
		struct ipv6hdr ip6;
		if (bpf_skb_load_bytes(skb, offset, &ip6, sizeof(ip6)) < 0)
			return TC_ACT_OK;

		/* Skip extension headers — only handle direct next header */
		if (ip6.nexthdr == IPPROTO_FRAGMENT)
			return TC_ACT_OK;

		l4_proto  = ip6.nexthdr;
		l4_offset = offset + sizeof(ip6);
		pkt_len   = (__u16)(bpf_ntohs(ip6.payload_len) + sizeof(ip6));
		__builtin_memcpy(src_ip, &ip6.saddr, 16);
		__builtin_memcpy(dst_ip, &ip6.daddr, 16);

		/*
		 * DSCP: upper 6 bits of the IPv6 Traffic Class field.
		 * Matches the XDP program's (bpf_ntohl(*(__u32 *)ip6) >> 22) & 0x3f.
		 * In struct ipv6hdr (big-endian): priority = upper 4 bits of TC,
		 * flow_lbl[0] upper 2 bits = lower 2 bits of TC.
		 */
		dscp = (((__u8)ip6.priority << 2) | (ip6.flow_lbl[0] >> 6)) & 0x3f;
	}

	/* --- L4 parse: TCP or UDP --- */
	if (l4_proto == IPPROTO_TCP) {
		struct tcphdr tcp;
		if (bpf_skb_load_bytes(skb, l4_offset, &tcp, sizeof(tcp)) < 0)
			return TC_ACT_OK;
		src_port = tcp.source;
		dst_port = tcp.dest;
	} else if (l4_proto == IPPROTO_UDP) {
		struct udphdr udp;
		if (bpf_skb_load_bytes(skb, l4_offset, &udp, sizeof(udp)) < 0)
			return TC_ACT_OK;
		src_port = udp.source;
		dst_port = udp.dest;
	} else {
		/* Unsupported L4 — not worth classifying */
		return TC_ACT_OK;
	}

	/* Skip tiny packets — keepalives, window probes, etc. */
	if (pkt_len < MIN_PKT_LEN)
		return TC_ACT_OK;

	/*
	 * --- DSCP classification → skb->mark ---
	 * Look up the daemon-populated dscp_class_map (shared with XDP path).
	 * Default to 0xAF02 (normal, offloadable) if no entry exists.
	 *
	 * DSCP→mark mapping:
	 *   CS1/AF1x/LE (bulk)        → 0xAF01
	 *   CS0/CS2/AF2x/CS3/AF3x    → 0xAF02  (default)
	 *   CS4/AF4x (interactive)   → 0xAF03
	 *   EF/CS5/CS6/CS7 (realtime)→ 0xAF04
	 */
	__u32 *class_mark = bpf_map_lookup_elem(&dscp_class_map, &dscp);
	skb->mark = class_mark ? *class_mark : 0xAF02;

	/*
	 * --- Submit flow event to shared ring buffer ---
	 * The daemon correlates TC-path events (egress_ifindex=0) with
	 * XDP-path events to fill in routing context.
	 */
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

		evt->ingress_ifindex = skb->ifindex;
		evt->egress_ifindex  = 0;   /* Unknown — no FIB lookup on TC path */
		__builtin_memcpy(evt->smac, eth.h_source, 6);
		__builtin_memcpy(evt->dmac, eth.h_dest, 6);
		evt->offload_cap   = 0;     /* Unknown — no iface_offload_map lookup */
		evt->is_bridge_fwd = 0;     /* Unknown — no FDB lookup */
		evt->pkt_len       = pkt_len;
		evt->dscp          = dscp;
		evt->_pad          = 0;

		bpf_ringbuf_submit(evt, 0);
	}

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
