// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright: Joel Wirāmu Pauling <aenertia@aenertia.net>
//
// Artifact Name: airoha-sync-daemon.c
// Purpose: Userspace daemon for the eBPF Soft Hook architecture on Airoha AN7581.
//
// Threads:
//   1. Netlink topology listener — populates iface_offload_map,
//      port_to_bridge_map, and mac_fdb_map from RTM_NEWLINK/RTM_NEWNEIGH.
//   2. Ring buffer consumer — receives flow_event from the XDP program,
//      builds internal flow table.
//   3. Debugfs poller — reads /sys/kernel/debug/ppe{0,1}/bind every 5s,
//      parses hardware flow stats, computes deltas, syncs to conntrack.
//   4. Orphan GC — periodically purges stale internal flow entries that
//      are no longer present in the hardware FOE table.
//   5. Reclassification worker — reloads dscp_class_map on SIGHUP;
//      future: monitors QDMA queue depths and tears down congested flows.
//
// See: ADR-001-ebpf-soft-hook.md

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <syslog.h>
#include <glob.h>
#include <time.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>
#include <linux/neighbour.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libmnl/libmnl.h>

/* ---------- BPF map pin paths (XDP pins maps here) ---------- */

#define MAP_PIN_DIR          "/sys/fs/bpf"
#define FDB_MAP_PATH         MAP_PIN_DIR "/mac_fdb_map"
#define IFACE_MAP_PATH       MAP_PIN_DIR "/iface_offload_map"
#define PORT_BRIDGE_MAP_PATH MAP_PIN_DIR "/port_to_bridge_map"
#define FLOW_EVENT_RB_PATH   MAP_PIN_DIR "/flow_event_rb"
#define DSCP_CLASS_MAP_PATH  MAP_PIN_DIR "/dscp_class_map"

/* ---------- debugfs paths for PPE stats (two PPE instances) ---------- */

#define PPE0_BIND_PATH "/sys/kernel/debug/ppe0/bind"
#define PPE1_BIND_PATH "/sys/kernel/debug/ppe1/bind"

#define DEBUGFS_POLL_INTERVAL 5   /* seconds */
#define GC_INTERVAL           120 /* seconds */
#define MAX_INTERNAL_FLOWS    65536

/* ---------- shared structures (must match XDP program) ---------- */

struct flow_key {
	uint32_t src_ip[4];
	uint32_t dst_ip[4];
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t l3_proto;
	uint8_t  l4_proto;
	uint8_t  padding;
};

struct flow_event {
	struct flow_key key;
	uint32_t ingress_ifindex;
	uint32_t egress_ifindex;
	uint8_t  smac[6];
	uint8_t  dmac[6];
	uint8_t  offload_cap;
	uint8_t  is_bridge_fwd;
	uint16_t pkt_len;
	uint8_t  dscp;
	uint8_t  _pad;
};

struct fdb_key {
	uint8_t  mac[6];
	uint16_t padding;
	uint32_t bridge_ifindex;
};

/* ---------- internal flow tracking ---------- */

struct internal_flow {
	struct flow_key key;
	uint64_t last_hw_bytes;
	uint64_t last_hw_pkts;
	time_t   last_seen;     /* last time seen in debugfs */
	time_t   first_seen;
	uint8_t  offload_cap;
	uint8_t  active;        /* 1 = in use */
};

static struct internal_flow flow_table[MAX_INTERNAL_FLOWS];
static pthread_mutex_t flow_table_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile int running = 1;

/* ---------- BPF map file descriptors ---------- */

static int fdb_map_fd          = -1;
static int iface_map_fd        = -1;
static int port_bridge_map_fd  = -1;
static int flow_event_rb_fd    = -1;
static struct ring_buffer *rb  = NULL;

static volatile sig_atomic_t reload_config = 0;

/* ---------- DSCP → mark classification defaults ---------- */

static const struct {
	uint8_t  dscp;
	uint32_t mark;
} default_dscp_map[] = {
	/* Bulk — offload (0xAF01) */
	{ 0,  0xAF02 },  /* CS0/DF — normal */
	{ 1,  0xAF01 },  /* LE */
	{ 8,  0xAF01 },  /* CS1 */
	{ 10, 0xAF01 },  /* AF11 */
	{ 12, 0xAF01 },  /* AF12 */
	{ 14, 0xAF01 },  /* AF13 */
	/* Normal — offload (0xAF02) */
	{ 16, 0xAF02 },  /* CS2 */
	{ 18, 0xAF02 },  /* AF21 */
	{ 20, 0xAF02 },  /* AF22 */
	{ 22, 0xAF02 },  /* AF23 */
	{ 24, 0xAF02 },  /* CS3 */
	{ 26, 0xAF02 },  /* AF31 */
	{ 28, 0xAF02 },  /* AF32 */
	{ 30, 0xAF02 },  /* AF33 */
	/* Interactive — keep on CPU for AQM (0xAF03) */
	{ 32, 0xAF03 },  /* CS4 */
	{ 34, 0xAF03 },  /* AF41 */
	{ 36, 0xAF03 },  /* AF42 */
	{ 38, 0xAF03 },  /* AF43 */
	/* Realtime — keep on CPU, highest priority (0xAF04) */
	{ 40, 0xAF04 },  /* CS5 */
	{ 44, 0xAF04 },  /* VA (Voice Admit) */
	{ 46, 0xAF04 },  /* EF */
	{ 48, 0xAF04 },  /* CS6 */
	{ 56, 0xAF04 },  /* CS7 */
};

/* ================================================================
 * SIGHUP handler — request dscp_class_map reload
 * ================================================================ */

static void handle_sighup(int sig)
{
	(void)sig;
	reload_config = 1;
}

/* ================================================================
 * DSCP classification map population
 * ================================================================ */

static void populate_dscp_class_map(void)
{
	int fd = bpf_obj_get(DSCP_CLASS_MAP_PATH);
	if (fd < 0) {
		syslog(LOG_WARNING, "dscp_class_map not found, classification disabled");
		return;
	}
	for (size_t i = 0; i < sizeof(default_dscp_map)/sizeof(default_dscp_map[0]); i++) {
		bpf_map_update_elem(fd, &default_dscp_map[i].dscp,
				    &default_dscp_map[i].mark, BPF_ANY);
	}
	close(fd);
	syslog(LOG_INFO, "populated dscp_class_map with %zu entries",
	       sizeof(default_dscp_map)/sizeof(default_dscp_map[0]));
}

/* ================================================================
 * UTILITY: Resolve offload capability from interface name
 * ================================================================ */

static uint8_t resolve_offload_capability(const char *ifname)
{
	char current[IFNAMSIZ];
	strncpy(current, ifname, IFNAMSIZ - 1);
	current[IFNAMSIZ - 1] = '\0';

	for (int depth = 0; depth < 5; depth++) {
		/* W1700K UBI DTS names: wan, lan2, lan3, lan4 */
		if (strncmp(current, "wan", 3) == 0 ||
		    strncmp(current, "eth", 3) == 0 ||
		    strncmp(current, "lan", 3) == 0)
			return 2; /* HWNAT capable */

		if (strncmp(current, "wlan", 4) == 0 ||
		    strncmp(current, "phy", 3) == 0)
			return 1; /* WED capable */

		/* Software-only interfaces */
		if (strncmp(current, "br-", 3) == 0 ||
		    strncmp(current, "veth", 4) == 0 ||
		    strncmp(current, "tun", 3) == 0 ||
		    strncmp(current, "tap", 3) == 0 ||
		    strncmp(current, "wg", 2) == 0)
			return 0;

		/* Walk lower devices */
		char pattern[256];
		snprintf(pattern, sizeof(pattern),
			 "/sys/class/net/%s/lower_*", current);
		glob_t gl;
		if (glob(pattern, 0, NULL, &gl) == 0 && gl.gl_pathc > 0) {
			char *lower = strrchr(gl.gl_pathv[0], '_');
			if (lower) {
				strncpy(current, lower + 1, IFNAMSIZ - 1);
				current[IFNAMSIZ - 1] = '\0';
				globfree(&gl);
				continue;
			}
		}
		globfree(&gl);
		break;
	}
	return 0;
}

/* ================================================================
 * INTERNAL FLOW TABLE OPERATIONS
 * ================================================================ */

static int flow_table_find(const struct flow_key *key)
{
	for (int i = 0; i < MAX_INTERNAL_FLOWS; i++) {
		if (flow_table[i].active &&
		    memcmp(&flow_table[i].key, key, sizeof(*key)) == 0)
			return i;
	}
	return -1;
}

static int flow_table_insert(const struct flow_key *key, uint8_t offload_cap)
{
	/* Check if already exists */
	int idx = flow_table_find(key);
	if (idx >= 0) {
		flow_table[idx].last_seen = time(NULL);
		return idx;
	}

	/* Find free slot */
	for (int i = 0; i < MAX_INTERNAL_FLOWS; i++) {
		if (!flow_table[i].active) {
			memcpy(&flow_table[i].key, key, sizeof(*key));
			flow_table[i].last_hw_bytes = 0;
			flow_table[i].last_hw_pkts  = 0;
			flow_table[i].first_seen    = time(NULL);
			flow_table[i].last_seen     = time(NULL);
			flow_table[i].offload_cap   = offload_cap;
			flow_table[i].active        = 1;
			return i;
		}
	}
	return -1; /* table full */
}

/* ================================================================
 * CONNTRACK SYNC
 * ================================================================ */

static void sync_hardware_counters(const struct flow_key *key,
				   uint64_t hw_bytes_delta,
				   uint64_t hw_pkts_delta,
				   int destroy)
{
	if (!destroy && hw_bytes_delta == 0 && hw_pkts_delta == 0)
		return;

	struct nfct_handle *h = nfct_open(CONNTRACK, 0);
	if (!h)
		return;

	struct nf_conntrack *ct = nfct_new();
	if (!ct) {
		nfct_close(h);
		return;
	}

	if (key->l3_proto == htons(ETH_P_IP)) {
		nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET);
		nfct_set_attr_u32(ct, ATTR_IPV4_SRC, key->src_ip[0]);
		nfct_set_attr_u32(ct, ATTR_IPV4_DST, key->dst_ip[0]);
	} else {
		nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET6);
		nfct_set_attr(ct, ATTR_IPV6_SRC, key->src_ip);
		nfct_set_attr(ct, ATTR_IPV6_DST, key->dst_ip);
	}

	nfct_set_attr_u8(ct, ATTR_L4PROTO, key->l4_proto);
	nfct_set_attr_u16(ct, ATTR_PORT_SRC, key->src_port);
	nfct_set_attr_u16(ct, ATTR_PORT_DST, key->dst_port);

	if (destroy) {
		nfct_query(h, NFCT_Q_DESTROY, ct);
	} else {
		nfct_set_attr_u64(ct, ATTR_ORIG_COUNTER_BYTES, hw_bytes_delta);
		nfct_set_attr_u64(ct, ATTR_ORIG_COUNTER_PACKETS, hw_pkts_delta);
		nfct_query(h, NFCT_Q_UPDATE, ct);
	}

	nfct_destroy(ct);
	nfct_close(h);
}

/* ================================================================
 * THREAD 1: Netlink topology listener
 * ================================================================ */

static int data_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);
	if (mnl_attr_type_valid(attr, NDA_MAX) < 0)
		return MNL_CB_OK;
	tb[type] = attr;
	return MNL_CB_OK;
}

static int link_cb(const struct nlmsghdr *nlh, void *data)
{
	struct ifinfomsg *ifi = mnl_nlmsg_get_payload(nlh);
	struct nlattr *tb[IFLA_MAX + 1] = {};
	mnl_attr_parse(nlh, sizeof(*ifi), data_attr_cb, tb);

	if (!tb[IFLA_IFNAME])
		return MNL_CB_OK;

	const char *ifname = mnl_attr_get_str(tb[IFLA_IFNAME]);
	uint32_t ifindex = ifi->ifi_index;

	if (nlh->nlmsg_type == RTM_NEWLINK) {
		if (iface_map_fd >= 0) {
			uint8_t cap = resolve_offload_capability(ifname);
			bpf_map_update_elem(iface_map_fd, &ifindex,
					    &cap, BPF_ANY);
		}

		if (tb[IFLA_MASTER] && port_bridge_map_fd >= 0) {
			uint32_t master = mnl_attr_get_u32(tb[IFLA_MASTER]);
			bpf_map_update_elem(port_bridge_map_fd, &ifindex,
					    &master, BPF_ANY);
		} else if (port_bridge_map_fd >= 0) {
			bpf_map_delete_elem(port_bridge_map_fd, &ifindex);
		}
	} else if (nlh->nlmsg_type == RTM_DELLINK) {
		if (iface_map_fd >= 0)
			bpf_map_delete_elem(iface_map_fd, &ifindex);
		if (port_bridge_map_fd >= 0)
			bpf_map_delete_elem(port_bridge_map_fd, &ifindex);
	}

	return MNL_CB_OK;
}

static int neigh_cb(const struct nlmsghdr *nlh, void *data)
{
	struct ndmsg *ndm = mnl_nlmsg_get_payload(nlh);

	if (ndm->ndm_family != AF_BRIDGE)
		return MNL_CB_OK;

	struct nlattr *tb[NDA_MAX + 1] = {};
	mnl_attr_parse(nlh, sizeof(*ndm), data_attr_cb, tb);

	if (!tb[NDA_LLADDR])
		return MNL_CB_OK;

	uint8_t *mac = mnl_attr_get_payload(tb[NDA_LLADDR]);
	uint32_t port_ifindex = ndm->ndm_ifindex;
	uint32_t bridge_ifindex = 0;

	if (port_bridge_map_fd >= 0)
		bpf_map_lookup_elem(port_bridge_map_fd, &port_ifindex,
				    &bridge_ifindex);
	if (bridge_ifindex == 0)
		bridge_ifindex = port_ifindex;

	struct fdb_key key = {};
	memcpy(key.mac, mac, 6);
	key.bridge_ifindex = bridge_ifindex;

	if (fdb_map_fd >= 0) {
		if (nlh->nlmsg_type == RTM_NEWNEIGH) {
			bpf_map_update_elem(fdb_map_fd, &key,
					    &port_ifindex, BPF_ANY);
		} else if (nlh->nlmsg_type == RTM_DELNEIGH) {
			bpf_map_delete_elem(fdb_map_fd, &key);
		}
	}

	return MNL_CB_OK;
}

static int route_multiplexer_cb(const struct nlmsghdr *nlh, void *data)
{
	if (nlh->nlmsg_type == RTM_NEWLINK ||
	    nlh->nlmsg_type == RTM_DELLINK)
		return link_cb(nlh, data);
	if (nlh->nlmsg_type == RTM_NEWNEIGH ||
	    nlh->nlmsg_type == RTM_DELNEIGH)
		return neigh_cb(nlh, data);
	return MNL_CB_OK;
}

static void *netlink_topology_listener(void *arg)
{
	struct mnl_socket *nl = mnl_socket_open(NETLINK_ROUTE);
	if (!nl) {
		fprintf(stderr, "netlink: failed to open socket\n");
		pthread_exit(NULL);
	}

	unsigned int groups = (1 << (RTNLGRP_LINK - 1)) |
			      (1 << (RTNLGRP_NEIGH - 1));
	if (mnl_socket_bind(nl, groups, MNL_SOCKET_AUTOPID) < 0) {
		fprintf(stderr, "netlink: bind failed\n");
		mnl_socket_close(nl);
		pthread_exit(NULL);
	}

	/* Dump existing links on startup */
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type  = RTM_GETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	struct ifinfomsg *ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifi));
	ifi->ifi_family = AF_UNSPEC;
	mnl_socket_sendto(nl, nlh, nlh->nlmsg_len);

	printf("netlink: topology listener started\n");

	while (running) {
		int ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			perror("netlink: recvfrom");
			continue;
		}
		mnl_cb_run(buf, ret, 0, 0, route_multiplexer_cb, NULL);
	}

	mnl_socket_close(nl);
	return NULL;
}

/* ================================================================
 * THREAD 2: Ring buffer consumer (flow events from XDP)
 * ================================================================ */

static int handle_flow_event(void *ctx, void *data, size_t data_sz)
{
	const struct flow_event *evt = data;

	if (data_sz < sizeof(*evt))
		return 0;

	pthread_mutex_lock(&flow_table_lock);
	flow_table_insert(&evt->key, evt->offload_cap);
	pthread_mutex_unlock(&flow_table_lock);

	return 0;
}

static void *ringbuf_consumer(void *arg)
{
	printf("ringbuf: flow event consumer started\n");

	rb = ring_buffer__new(flow_event_rb_fd, handle_flow_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "ringbuf: failed to create ring buffer\n");
		pthread_exit(NULL);
	}

	while (running) {
		int err = ring_buffer__poll(rb, 1000);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "ringbuf: poll error %d\n", err);
			break;
		}
	}

	return NULL;
}

/* ================================================================
 * THREAD 3: Debugfs poller (PPE hardware stats)
 *
 * Reads /sys/kernel/debug/ppe{0,1}/bind which lists bound FOE entries.
 * Expected format per line (kernel airoha_ppe.c debugfs output):
 *   hash=XXXX state=BIND ...
 *   type=IPV4_HNAPT src=A.B.C.D:port dst=E.F.G.H:port
 *   packets=NNN bytes=NNN
 *
 * The exact format depends on the kernel version. We parse conservatively.
 * ================================================================ */

struct ppe_flow_stats {
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t  l4_proto;
	uint64_t packets;
	uint64_t bytes;
	int      valid;
};

/*
 * Parse a single debugfs bind file and update internal flow table.
 * This is a best-effort parser — if the format changes we log a
 * warning and skip unrecognised entries.
 */
static void poll_ppe_debugfs(const char *path)
{
	FILE *f = fopen(path, "r");
	if (!f)
		return;

	char line[512];
	struct ppe_flow_stats current = {};

	while (fgets(line, sizeof(line), f)) {
		uint32_t a, b, c, d;
		unsigned int port;
		uint64_t val;

		/* Look for src=A.B.C.D:port */
		if (sscanf(line, " src=%u.%u.%u.%u:%u",
			   &a, &b, &c, &d, &port) == 5) {
			current.src_ip = htonl((a << 24) | (b << 16) |
					       (c << 8) | d);
			current.src_port = htons(port);
			current.valid |= 1;
		}

		if (sscanf(line, " dst=%u.%u.%u.%u:%u",
			   &a, &b, &c, &d, &port) == 5) {
			current.dst_ip = htonl((a << 24) | (b << 16) |
					       (c << 8) | d);
			current.dst_port = htons(port);
			current.valid |= 2;
		}

		/* Look for packets=NNN */
		char *pp = strstr(line, "packets=");
		if (pp && sscanf(pp, "packets=%lu", &val) == 1)
			current.packets = val;

		/* Look for bytes=NNN */
		char *bp = strstr(line, "bytes=");
		if (bp && sscanf(bp, "bytes=%lu", &val) == 1)
			current.bytes = val;

		/* Detect entry boundary (blank line or new hash=) */
		if (strstr(line, "hash=") && current.valid == 3) {
			/* Flush previous entry */
			goto flush_entry;
		}
		continue;

flush_entry:
		if (current.valid == 3) {
			struct flow_key fk = {};
			fk.src_ip[0] = current.src_ip;
			fk.dst_ip[0] = current.dst_ip;
			fk.src_port  = current.src_port;
			fk.dst_port  = current.dst_port;
			fk.l3_proto  = htons(ETH_P_IP);
			fk.l4_proto  = current.l4_proto ? current.l4_proto : 6;

			pthread_mutex_lock(&flow_table_lock);
			int idx = flow_table_find(&fk);
			if (idx >= 0) {
				struct internal_flow *fl = &flow_table[idx];
				uint64_t b_delta = 0, p_delta = 0;

				if (current.bytes > fl->last_hw_bytes)
					b_delta = current.bytes - fl->last_hw_bytes;
				if (current.packets > fl->last_hw_pkts)
					p_delta = current.packets - fl->last_hw_pkts;

				fl->last_hw_bytes = current.bytes;
				fl->last_hw_pkts  = current.packets;
				fl->last_seen     = time(NULL);

				pthread_mutex_unlock(&flow_table_lock);

				sync_hardware_counters(&fk, b_delta, p_delta, 0);
			} else {
				pthread_mutex_unlock(&flow_table_lock);
			}
		}
		memset(&current, 0, sizeof(current));
	}

	/* Flush last entry if pending */
	if (current.valid == 3) {
		struct flow_key fk = {};
		fk.src_ip[0] = current.src_ip;
		fk.dst_ip[0] = current.dst_ip;
		fk.src_port  = current.src_port;
		fk.dst_port  = current.dst_port;
		fk.l3_proto  = htons(ETH_P_IP);
		fk.l4_proto  = current.l4_proto ? current.l4_proto : 6;

		pthread_mutex_lock(&flow_table_lock);
		int idx = flow_table_find(&fk);
		if (idx >= 0) {
			struct internal_flow *fl = &flow_table[idx];
			uint64_t b_delta = 0, p_delta = 0;

			if (current.bytes > fl->last_hw_bytes)
				b_delta = current.bytes - fl->last_hw_bytes;
			if (current.packets > fl->last_hw_pkts)
				p_delta = current.packets - fl->last_hw_pkts;

			fl->last_hw_bytes = current.bytes;
			fl->last_hw_pkts  = current.packets;
			fl->last_seen     = time(NULL);

			pthread_mutex_unlock(&flow_table_lock);

			sync_hardware_counters(&fk, b_delta, p_delta, 0);
		} else {
			pthread_mutex_unlock(&flow_table_lock);
		}
	}

	fclose(f);
}

static void *debugfs_poller(void *arg)
{
	printf("debugfs: PPE stats poller started (interval=%ds)\n",
	       DEBUGFS_POLL_INTERVAL);

	while (running) {
		sleep(DEBUGFS_POLL_INTERVAL);
		poll_ppe_debugfs(PPE0_BIND_PATH);
		poll_ppe_debugfs(PPE1_BIND_PATH);
	}
	return NULL;
}

/* ================================================================
 * THREAD 4: Orphan garbage collector
 *
 * Purges internal flow entries that haven't been seen in debugfs
 * for longer than GC_INTERVAL seconds.
 * ================================================================ */

static void *orphan_garbage_collector(void *arg)
{
	printf("gc: orphan flow garbage collector started (interval=%ds)\n",
	       GC_INTERVAL);

	while (running) {
		sleep(GC_INTERVAL);

		time_t now = time(NULL);
		int purged = 0;

		pthread_mutex_lock(&flow_table_lock);
		for (int i = 0; i < MAX_INTERNAL_FLOWS; i++) {
			if (!flow_table[i].active)
				continue;

			/* If not seen in debugfs for GC_INTERVAL, purge */
			if ((now - flow_table[i].last_seen) > GC_INTERVAL) {
				flow_table[i].active = 0;
				purged++;
			}
		}
		pthread_mutex_unlock(&flow_table_lock);

		if (purged > 0)
			printf("gc: purged %d stale flow entries\n", purged);
	}
	return NULL;
}

/* ================================================================
 * THREAD 5: Reclassification worker
 *
 * Reloads dscp_class_map on SIGHUP.  Future: monitor QDMA queue
 * depths and tear down flows from congested queues.
 * ================================================================ */

static void *reclassification_worker(void *arg)
{
	(void)arg;
	syslog(LOG_INFO, "reclassification worker started");

	while (running) {
		sleep(10);

		if (reload_config) {
			syslog(LOG_INFO, "reloading dscp_class_map (SIGHUP)");
			populate_dscp_class_map();
			reload_config = 0;
		}
	}
	return NULL;
}

/* ================================================================
 * SIGNAL HANDLING
 * ================================================================ */

static void signal_handler(int sig)
{
	printf("received signal %d, shutting down\n", sig);
	running = 0;
}

/* ================================================================
 * MAIN
 * ================================================================ */

int main(int argc, char **argv)
{
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGHUP, handle_sighup);

	syslog(LOG_INFO, "airoha-sync-daemon starting");

	/*
	 * Wait for BPF maps to appear with exponential backoff.
	 * The XDP init script may not have finished pinning maps yet,
	 * especially on first boot when interfaces are still coming up.
	 */
	int backoff = 1;
	int max_attempts = 12; /* ~68s total: 1+2+4+8+8+8+8+8+8+8+8+8 */

	for (int attempt = 0; attempt < max_attempts; attempt++) {
		fdb_map_fd         = bpf_obj_get(FDB_MAP_PATH);
		iface_map_fd       = bpf_obj_get(IFACE_MAP_PATH);
		port_bridge_map_fd = bpf_obj_get(PORT_BRIDGE_MAP_PATH);
		flow_event_rb_fd   = bpf_obj_get(FLOW_EVENT_RB_PATH);

		/* At least one map available — proceed */
		if (iface_map_fd >= 0 || fdb_map_fd >= 0 || flow_event_rb_fd >= 0)
			break;

		syslog(LOG_INFO, "waiting for BPF maps (attempt %d/%d, next retry in %ds)",
		       attempt + 1, max_attempts, backoff);
		sleep(backoff);
		if (backoff < 8)
			backoff *= 2;
	}

	if (iface_map_fd < 0)
		syslog(LOG_WARNING, "iface_offload_map not found at %s",
		       IFACE_MAP_PATH);
	if (fdb_map_fd < 0)
		syslog(LOG_WARNING, "mac_fdb_map not found at %s",
		       FDB_MAP_PATH);
	if (port_bridge_map_fd < 0)
		syslog(LOG_WARNING, "port_to_bridge_map not found at %s",
		       PORT_BRIDGE_MAP_PATH);
	if (flow_event_rb_fd < 0)
		syslog(LOG_WARNING, "flow_event_rb not found at %s",
		       FLOW_EVENT_RB_PATH);

	/*
	 * The daemon can still function partially without all maps:
	 * - Without ring buffer: no new flows discovered, but debugfs
	 *   polling still works for manually tracked flows.
	 * - Without iface/fdb maps: netlink listener still runs but
	 *   map updates silently fail.
	 *
	 * Only bail out if nothing is usable after all retries.
	 */
	if (iface_map_fd < 0 && fdb_map_fd < 0 && flow_event_rb_fd < 0) {
		syslog(LOG_ERR, "no BPF maps found after %d attempts; is XDP loaded?",
		       max_attempts);
		exit(EXIT_FAILURE);
	}

	/* Initialise flow table */
	memset(flow_table, 0, sizeof(flow_table));

	/* Populate DSCP classification map with defaults */
	populate_dscp_class_map();

	/* Launch threads */
	pthread_t nl_thread, rb_thread, dbgfs_thread, gc_thread, reclass_thread;

	pthread_create(&nl_thread, NULL, netlink_topology_listener, NULL);

	if (flow_event_rb_fd >= 0)
		pthread_create(&rb_thread, NULL, ringbuf_consumer, NULL);

	pthread_create(&dbgfs_thread, NULL, debugfs_poller, NULL);
	pthread_create(&gc_thread, NULL, orphan_garbage_collector, NULL);
	pthread_create(&reclass_thread, NULL, reclassification_worker, NULL);

	/* Wait for threads */
	pthread_join(nl_thread, NULL);
	if (flow_event_rb_fd >= 0)
		pthread_join(rb_thread, NULL);
	pthread_join(dbgfs_thread, NULL);
	pthread_join(gc_thread, NULL);
	pthread_join(reclass_thread, NULL);

	/* Cleanup */
	if (rb)
		ring_buffer__free(rb);

	printf("airoha-sync-daemon exiting\n");
	return 0;
}
