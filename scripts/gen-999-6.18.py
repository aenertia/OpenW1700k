#!/usr/bin/env python3
"""Generate the 999-airoha-eth-xdp-lro-support.patch for kernel 6.18.

Reads pre-999 source files from /tmp/airoha-pre999/,
applies all XDP/LRO/QoS changes at exact line positions,
writes modified files to /tmp/airoha-post999/,
generates unified diff as the final patch.

Line numbers are from the pre-999 6.18 source (post all other patches).
"""

import os, subprocess

PREDIR = '/tmp/airoha-pre999'
POSTDIR = '/tmp/airoha-post999'
PATCHDIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPATCH = os.path.join(PATCHDIR, 'target/linux/airoha/patches-6.18/999-airoha-eth-xdp-lro-support.patch')

# ============================================================
# Large code blocks — all adapted for 6.18 with bug fixes
# ============================================================

INCLUDES_ETH_C = {
    # After line containing 'platform_device.h' (line 9), add:
    'platform_device': ['#include <linux/ip.h>\n', '#include <linux/ipv6.h>\n'],
    # After line containing 'tcp.h' (line 10), add:
    'tcp.h': ['#include <linux/unaligned.h>\n'],
    # After line containing 'u64_stats_sync.h' (line 11), add:
    'u64_stats_sync': ['#include <net/dsfield.h>\n', '#include <net/tcp.h>\n'],
    # Before 'airoha_eth.h' (line 18), add:
    'airoha_regs': ['#include <trace/events/xdp.h>\n'],
}

LRO_INIT_FUNCS = r"""
static void airoha_fe_lro_init_rx_queue(struct airoha_eth *eth, int id,
					int lro_queue_index, int qid,
					int nbuf, int buf_size)
{
	airoha_fe_rmw(eth, REG_CDM_LRO_LIMIT(id),
		      CDM_LRO_AGG_NUM_MASK | CDM_LRO_AGG_SIZE_MASK,
		      FIELD_PREP(CDM_LRO_AGG_NUM_MASK, nbuf) |
		      FIELD_PREP(CDM_LRO_AGG_SIZE_MASK, buf_size));
	airoha_fe_rmw(eth, REG_CDM_LRO_AGE_TIME(id),
		      CDM_LRO_AGE_TIME_MASK | CDM_LRO_AGG_TIME_MASK,
		      FIELD_PREP(CDM_LRO_AGE_TIME_MASK,
				 AIROHA_RXQ_LRO_MAX_AGE_TIME) |
		      FIELD_PREP(CDM_LRO_AGG_TIME_MASK,
				 AIROHA_RXQ_LRO_MAX_AGG_TIME));
	airoha_fe_rmw(eth, REG_CDM_LRO_RXQ(id, lro_queue_index),
		      LRO_RXQ_MASK(lro_queue_index),
		      qid << __ffs(LRO_RXQ_MASK(lro_queue_index)));
	airoha_fe_set(eth, REG_CDM_LRO_EN(id), BIT(lro_queue_index));
}

static void airoha_fe_lro_disable(struct airoha_eth *eth, int id)
{
	int i;

	airoha_fe_clear(eth, REG_CDM_LRO_LIMIT(id),
			CDM_LRO_AGG_NUM_MASK | CDM_LRO_AGG_SIZE_MASK);
	airoha_fe_clear(eth, REG_CDM_LRO_AGE_TIME(id),
			CDM_LRO_AGE_TIME_MASK | CDM_LRO_AGG_TIME_MASK);
	airoha_fe_clear(eth, REG_CDM_LRO_EN(id), LRO_RXQ_EN_MASK);
	for (i = 0; i < AIROHA_MAX_NUM_LRO_QUEUES; i++)
		airoha_fe_clear(eth, REG_CDM_LRO_RXQ(id, i), LRO_RXQ_MASK(i));
}

"""

XDP_TX_AND_HELPERS = r"""
/* XDP TX using linked-list descriptor model (kernel 6.18+).
 * Converts the XDP buffer to an xdp_frame to hold a page reference
 * until TX completion, avoiding use-after-free with page pool recycling.
 */
static int airoha_xdp_tx(struct airoha_qdma *qdma, struct xdp_buff *xdp)
{
	struct xdp_frame *xdpf;
	struct airoha_queue *q = &qdma->q_tx[0];
	struct airoha_qdma_desc *desc;
	struct airoha_queue_entry *e;
	dma_addr_t dma_addr;
	int index;
	u32 val;

	xdpf = xdp_convert_buff_to_frame(xdp);
	if (unlikely(!xdpf))
		return -EOVERFLOW;

	spin_lock_bh(&q->lock);

	if (q->queued >= q->ndesc - 1 || list_empty(&q->tx_list)) {
		spin_unlock_bh(&q->lock);
		xdp_return_frame(xdpf);
		return -ENOSPC;
	}

	e = list_first_entry(&q->tx_list, struct airoha_queue_entry, list);
	index = e - q->entry;
	desc = &q->desc[index];

	dma_addr = dma_map_single(qdma->eth->dev, xdpf->data,
				  xdpf->len, DMA_TO_DEVICE);
	if (dma_mapping_error(qdma->eth->dev, dma_addr)) {
		spin_unlock_bh(&q->lock);
		xdp_return_frame(xdpf);
		return -ENOMEM;
	}

	list_del_init(&e->list);

	e->dma_addr = dma_addr;
	e->dma_len = xdpf->len | AIROHA_TXQ_XDP_FRAME;
	e->skb = (struct sk_buff *)xdpf;

	val = FIELD_PREP(QDMA_DESC_LEN_MASK, xdpf->len);
	WRITE_ONCE(desc->ctrl, cpu_to_le32(val));
	WRITE_ONCE(desc->addr, cpu_to_le32(dma_addr));
	WRITE_ONCE(desc->data, 0);
	WRITE_ONCE(desc->msg0, 0);
	WRITE_ONCE(desc->msg1, 0);
	WRITE_ONCE(desc->msg2, 0);
	WRITE_ONCE(desc->msg3, 0);

	q->queued++;

	if (!list_empty(&q->tx_list)) {
		struct airoha_queue_entry *next;

		next = list_first_entry(&q->tx_list,
					struct airoha_queue_entry, list);
		airoha_qdma_rmw(qdma, REG_TX_CPU_IDX(0),
				TX_RING_CPU_IDX_MASK,
				FIELD_PREP(TX_RING_CPU_IDX_MASK,
					   next - q->entry));
	}

	spin_unlock_bh(&q->lock);
	return 0;
}

static bool airoha_qdma_is_lro_rx_queue(struct airoha_queue *q,
					struct airoha_qdma *qdma)
{
	int qid = q - &qdma->q_rx[0];

	BUILD_BUG_ON(hweight32(AIROHA_RXQ_LRO_EN_MASK) >
		     AIROHA_MAX_NUM_LRO_QUEUES);

	return !!(AIROHA_RXQ_LRO_EN_MASK & BIT(qid));
}

static int airoha_qdma_lro_rx_process(struct airoha_queue *q,
				      struct airoha_qdma_desc *desc)
{
	u32 msg1 = le32_to_cpu(desc->msg1), msg2 = le32_to_cpu(desc->msg2);
	u32 th_off, tcp_ack_seq, msg3 = le32_to_cpu(desc->msg3);
	bool ipv4 = FIELD_GET(QDMA_ETH_RXMSG_IP4_MASK, msg1);
	bool ipv6 = FIELD_GET(QDMA_ETH_RXMSG_IP6_MASK, msg1);
	struct sk_buff *skb = q->skb;
	u16 tcp_win, l2_len;
	struct tcphdr *th;

	if (FIELD_GET(QDMA_ETH_RXMSG_AGG_COUNT_MASK, msg2) <= 1)
		return 0;

	if (!ipv4 && !ipv6)
		return -EOPNOTSUPP;

	l2_len = FIELD_GET(QDMA_ETH_RXMSG_L2_LEN_MASK, msg2);
	if (ipv4) {
		u16 agg_len = FIELD_GET(QDMA_ETH_RXMSG_AGG_LEN_MASK, msg3);
		struct iphdr *iph = (struct iphdr *)(skb->data + l2_len);

		if (iph->protocol != IPPROTO_TCP)
			return -EOPNOTSUPP;

		iph->tot_len = cpu_to_be16(agg_len);
		iph->check = 0;
		iph->check = ip_fast_csum((void *)iph, iph->ihl);
		th_off = l2_len + (iph->ihl << 2);
	} else {
		struct ipv6hdr *ip6h = (struct ipv6hdr *)(skb->data + l2_len);
		u32 len, desc_ctrl = le32_to_cpu(desc->ctrl);

		if (ip6h->nexthdr != NEXTHDR_TCP)
			return -EOPNOTSUPP;

		len = FIELD_GET(QDMA_DESC_LEN_MASK, desc_ctrl);
		ip6h->payload_len = cpu_to_be16(len - l2_len - sizeof(*ip6h));
		th_off = l2_len + sizeof(*ip6h);
	}

	tcp_win = FIELD_GET(QDMA_ETH_RXMSG_TCP_WIN_MASK, msg3);
	tcp_ack_seq = le32_to_cpu(desc->data);

	th = (struct tcphdr *)(skb->data + th_off);
	th->ack_seq = cpu_to_be32(tcp_ack_seq);
	th->window = cpu_to_be16(tcp_win);

	if (th->doff == sizeof(*th) + TCPOLEN_TSTAMP_ALIGNED) {
		__be32 *topt = (__be32 *)(th + 1);

		if (*topt == cpu_to_be32((TCPOPT_NOP << 24) |
					 (TCPOPT_NOP << 16) |
					 (TCPOPT_TIMESTAMP << 8) |
					 TCPOLEN_TIMESTAMP)) {
			u32 tcp_ts_reply = le32_to_cpu(desc->tcp_ts_reply);

			put_unaligned_be32(tcp_ts_reply, topt + 2);
		}
	}

	return 0;
}

"""

INIT_RX_PP = r"""
static int airoha_qdma_init_rx_pp(struct airoha_queue *q, bool lro_queue)
{
	const struct page_pool_params pp_params = {
		.order = lro_queue ? AIROHA_LRO_PAGE_ORDER : 0,
		.pool_size = 256,
		.flags = PP_FLAG_DMA_MAP | PP_FLAG_DMA_SYNC_DEV,
		.dma_dir = DMA_FROM_DEVICE,
		.max_len = lro_queue ? PAGE_SIZE << AIROHA_LRO_PAGE_ORDER
				     : PAGE_SIZE,
		.nid = NUMA_NO_NODE,
		.dev = q->qdma->eth->dev,
		.napi = &q->napi,
	};

	q->buf_size = pp_params.max_len / (2 * (1 + lro_queue));
	q->page_pool = page_pool_create(&pp_params);
	if (IS_ERR(q->page_pool)) {
		int err = PTR_ERR(q->page_pool);

		q->page_pool = NULL;
		return err;
	}

	return 0;
}

"""

RX_QUEUE_DEINIT = r"""
static void airoha_qdma_rx_queue_deinit(struct airoha_queue *q)
{
	if (xdp_rxq_info_is_reg(&q->xdp_rxq))
		xdp_rxq_info_unreg(&q->xdp_rxq);

	airoha_qdma_cleanup_rx_queue(q);
	if (q->page_pool) {
		page_pool_destroy(q->page_pool);
		q->page_pool = NULL;
	}
}

"""

SET_FEATURES_FUNC = r"""
static int airoha_dev_set_features(struct net_device *dev,
				   netdev_features_t features)
{
	netdev_features_t diff = dev->features ^ features;
	struct airoha_gdm_port *port = netdev_priv(dev);
	struct airoha_qdma *qdma = port->qdma;
	struct airoha_eth *eth = qdma->eth;
	int i;

	if (!(diff & NETIF_F_LRO))
		return 0;

	for (i = 0; i < ARRAY_SIZE(eth->qdma); i++) {
		struct airoha_qdma *q = &eth->qdma[i];
		int j;

		airoha_qdma_stop_napi(q);
		airoha_qdma_clear(q, REG_QDMA_GLOBAL_CFG,
				  GLOBAL_CFG_TX_DMA_EN_MASK |
				  GLOBAL_CFG_RX_DMA_EN_MASK);
		usleep_range(5000, 10000);

		for (j = 0; j < ARRAY_SIZE(q->q_rx); j++) {
			struct airoha_queue *rq = &q->q_rx[j];
			bool lro_queue;
			int err;

			if (!rq->ndesc)
				continue;

			lro_queue = airoha_qdma_is_lro_rx_queue(rq, q);
			if (!lro_queue)
				continue;

			if (xdp_rxq_info_is_reg(&rq->xdp_rxq))
				xdp_rxq_info_unreg(&rq->xdp_rxq);
			airoha_qdma_cleanup_rx_queue(rq);
			if (rq->page_pool) {
				page_pool_destroy(rq->page_pool);
				rq->page_pool = NULL;
			}

			err = airoha_qdma_init_rx_pp(rq, lro_queue);
			if (err)
				return err;

			if (xdp_rxq_info_reg(&rq->xdp_rxq, eth->napi_dev, j,
					     rq->napi.napi_id))
				return -ENOMEM;
			if (xdp_rxq_info_reg_mem_model(&rq->xdp_rxq,
						       MEM_TYPE_PAGE_POOL,
						       rq->page_pool))
				return -ENOMEM;

			airoha_qdma_fill_rx_queue(rq);
		}

		airoha_qdma_set(q, REG_QDMA_GLOBAL_CFG,
				GLOBAL_CFG_TX_DMA_EN_MASK |
				GLOBAL_CFG_RX_DMA_EN_MASK);
		airoha_qdma_start_napi(q);
	}

	if (features & NETIF_F_LRO) {
		for (i = 0; i < ARRAY_SIZE(eth->qdma); i++) {
			struct airoha_qdma *q = &eth->qdma[i];
			int j, cdm_id, lro_idx = 0;

			for (j = 0; j < ARRAY_SIZE(q->q_rx); j++) {
				if (!q->q_rx[j].ndesc)
					continue;
				if (!airoha_qdma_is_lro_rx_queue(&q->q_rx[j], q))
					continue;
				cdm_id = i + 1;
				airoha_fe_lro_init_rx_queue(eth, cdm_id,
							    lro_idx, j,
							    q->q_rx[j].buf_size / ETH_DATA_LEN,
							    q->q_rx[j].buf_size);
				lro_idx++;
			}
		}
	} else {
		for (i = 0; i < ARRAY_SIZE(eth->qdma); i++)
			airoha_fe_lro_disable(eth, i + 1);
	}

	return 0;
}

"""

XDP_SETUP_FUNCS = r"""
static int airoha_xdp_setup(struct net_device *dev, struct bpf_prog *prog)
{
	struct airoha_gdm_port *port = netdev_priv(dev);
	struct bpf_prog *old_prog;

	if (prog && dev->mtu > ETH_DATA_LEN) {
		netdev_err(dev, "XDP not supported with jumbo frames\n");
		return -EOPNOTSUPP;
	}

	old_prog = rcu_replace_pointer(port->xdp_prog, prog,
				       lockdep_rtnl_is_held());
	if (old_prog)
		bpf_prog_put(old_prog);

	if (prog)
		xdp_set_features_flag(dev, NETDEV_XDP_ACT_BASIC |
				      NETDEV_XDP_ACT_REDIRECT);
	else
		xdp_clear_features_flag(dev);

	return 0;
}

static int airoha_dev_bpf(struct net_device *dev, struct netdev_bpf *bpf)
{
	switch (bpf->command) {
	case XDP_SETUP_PROG:
		return airoha_xdp_setup(dev, bpf->prog);
	default:
		return -EOPNOTSUPP;
	}
}

/* XDP xmit using linked-list descriptor model (kernel 6.18+). */
static int airoha_dev_xdp_xmit(struct net_device *dev, int n,
				struct xdp_frame **frames, u32 flags)
{
	struct airoha_gdm_port *port = netdev_priv(dev);
	struct airoha_qdma *qdma = port->qdma;
	struct airoha_queue *q = &qdma->q_tx[0];
	int i, sent = 0;

	spin_lock_bh(&q->lock);

	for (i = 0; i < n; i++) {
		struct xdp_frame *xdpf = frames[i];
		struct airoha_qdma_desc *desc;
		struct airoha_queue_entry *e;
		dma_addr_t dma_addr;
		int index;
		u32 val;

		if (q->queued >= q->ndesc - 1 || list_empty(&q->tx_list))
			break;

		e = list_first_entry(&q->tx_list, struct airoha_queue_entry,
				     list);
		index = e - q->entry;
		desc = &q->desc[index];

		dma_addr = dma_map_single(qdma->eth->dev, xdpf->data,
					  xdpf->len, DMA_TO_DEVICE);
		if (dma_mapping_error(qdma->eth->dev, dma_addr)) {
			xdp_return_frame_rx_napi(xdpf);
			continue;
		}

		list_del_init(&e->list);
		e->dma_addr = dma_addr;
		e->dma_len = xdpf->len | AIROHA_TXQ_XDP_FRAME;
		e->skb = (struct sk_buff *)xdpf;

		val = FIELD_PREP(QDMA_DESC_LEN_MASK, xdpf->len);
		WRITE_ONCE(desc->ctrl, cpu_to_le32(val));
		WRITE_ONCE(desc->addr, cpu_to_le32(dma_addr));
		WRITE_ONCE(desc->data, 0);
		WRITE_ONCE(desc->msg0, 0);
		WRITE_ONCE(desc->msg1, 0);
		WRITE_ONCE(desc->msg2, 0);
		WRITE_ONCE(desc->msg3, 0);

		q->queued++;
		sent++;
	}

	if (sent && !list_empty(&q->tx_list)) {
		struct airoha_queue_entry *next;

		next = list_first_entry(&q->tx_list,
					struct airoha_queue_entry, list);
		airoha_qdma_rmw(qdma, REG_TX_CPU_IDX(0),
				TX_RING_CPU_IDX_MASK,
				FIELD_PREP(TX_RING_CPU_IDX_MASK,
					   next - q->entry));
	}

	spin_unlock_bh(&q->lock);

	return sent;
}

"""

DSCP_TO_QUEUE = r"""
/*
 * Map DSCP (0-63) to QDMA channel (0-3) and queue (0-7) for hardware
 * ETS scheduling. 4 channels x 8 queues = 32 hardware queues.
 *
 * Channel assignment (SP between channels, WRR within):
 *   ch0 = bulk/scavenger   ch1 = normal/best-effort
 *   ch2 = interactive      ch3 = realtime/control
 */
static void airoha_dscp_to_queue(u8 dscp, u8 *channel, u8 *queue)
{
	u8 ch = 1, q = 0;

	if (dscp <= 1 || (dscp >= 8 && dscp <= 15)) {
		ch = 0;
		q = dscp > 1 ? 2 : 0;
	} else if (dscp >= 16 && dscp <= 31) {
		ch = 1;
		q = (dscp >= 24) ? 4 : 2;
	} else if (dscp >= 32 && dscp <= 39) {
		ch = 2;
		q = 4;
	} else if (dscp >= 40 && dscp <= 47) {
		ch = 3;
		q = 6;
	} else if (dscp >= 48) {
		ch = 3;
		q = 7;
	}

	*channel = ch & 0x3;
	*queue = q & 0x7;
}

"""

ETH_H_DEFINES = """#define AIROHA_XDP_HEADROOM\t\tXDP_PACKET_HEADROOM
/* Flag stored in upper bits of dma_len to mark XDP frame entries. */
#define AIROHA_TXQ_XDP_FRAME\t\tBIT(15)
#define AIROHA_TXQ_LEN_MASK\t\tGENMASK(14, 0)

#define AIROHA_LRO_PAGE_ORDER\t\t2
#define AIROHA_MAX_NUM_LRO_QUEUES\t8
#define AIROHA_RXQ_LRO_EN_MASK\t\t0xff
#define AIROHA_RXQ_LRO_MAX_AGG_TIME\t100
#define AIROHA_RXQ_LRO_MAX_AGE_TIME\t2000 /* 1ms */

#define AIROHA_HW_FEATURES\t\t\t\\
\t(NETIF_F_IP_CSUM | NETIF_F_RXCSUM |\t\\
\t NETIF_F_TSO6 | NETIF_F_IPV6_CSUM |\t\\
\t NETIF_F_SG | NETIF_F_TSO | NETIF_F_HW_TC)

"""

LRO_REGS = """
#define REG_CDM_LRO_RXQ(_n, _m)\t(CDM_BASE(_n) + 0x78 + ((_m) & 0x4))
#define LRO_RXQ_MASK(_n)\t\t(GENMASK(4, 0) << (((_n) & 0x3) << 3))

#define REG_CDM_LRO_EN(_n)\t\t(CDM_BASE(_n) + 0x80)
#define LRO_RXQ_EN_MASK\t\t\tGENMASK(7, 0)

#define REG_CDM_LRO_LIMIT(_n)\t\t(CDM_BASE(_n) + 0x84)
#define CDM_LRO_AGG_NUM_MASK\t\tGENMASK(23, 16)
#define CDM_LRO_AGG_SIZE_MASK\t\tGENMASK(15, 0)

#define REG_CDM_LRO_AGE_TIME(_n)\t(CDM_BASE(_n) + 0x88)
#define CDM_LRO_AGE_TIME_MASK\t\tGENMASK(31, 16)
#define CDM_LRO_AGG_TIME_MASK\t\tGENMASK(15, 0)

"""

RX_MSG_MASKS = """
/* RX MSG2 */
#define QDMA_ETH_RXMSG_AGG_COUNT_MASK\tGENMASK(27, 24)
#define QDMA_ETH_RXMSG_L2_LEN_MASK\tGENMASK(23, 16)
/* RX MSG3 */
#define QDMA_ETH_RXMSG_TCP_WIN_MASK\tGENMASK(31, 16)
#define QDMA_ETH_RXMSG_AGG_LEN_MASK\tGENMASK(15, 0)

"""

# ============================================================
# Helper: find line number by content
# ============================================================
def find_line(lines, pattern, start=0):
    for i in range(start, len(lines)):
        if pattern in lines[i]:
            return i
    raise ValueError(f"Pattern not found: {pattern}")

def find_func_end(lines, start):
    """Find closing } of a function starting at 'start'."""
    depth = 0
    for i in range(start, len(lines)):
        depth += lines[i].count('{') - lines[i].count('}')
        if depth == 0 and '}' in lines[i]:
            return i
    raise ValueError(f"Function end not found from line {start}")

def insert_after(lines, idx, text):
    """Insert text block after line idx."""
    new_lines = text.split('\n')
    # Remove trailing empty if text ends with \n
    if new_lines and new_lines[-1] == '':
        new_lines = new_lines[:-1]
    for j, nl in enumerate(new_lines):
        lines.insert(idx + 1 + j, nl + '\n')
    return len(new_lines)

# ============================================================
# Apply changes to airoha_eth.c
# ============================================================
def patch_eth_c():
    with open(f'{PREDIR}/airoha_eth.c') as f:
        lines = f.readlines()

    # 1. Add includes
    i = find_line(lines, 'platform_device.h')
    offset = insert_after(lines, i, '#include <linux/ip.h>\n#include <linux/ipv6.h>')

    i = find_line(lines, '<linux/tcp.h>')
    offset += insert_after(lines, i, '#include <linux/unaligned.h>')

    i = find_line(lines, 'u64_stats_sync.h')
    offset += insert_after(lines, i, '#include <net/dsfield.h>\n#include <net/tcp.h>')

    i = find_line(lines, '"airoha_regs.h"')
    offset += insert_after(lines, i, '#include <trace/events/xdp.h>')

    # 2. Insert LRO init funcs after airoha_fe_crsn_qsel_init
    i = find_line(lines, 'static void airoha_fe_crsn_qsel_init')
    end = find_func_end(lines, i)
    offset += insert_after(lines, end, LRO_INIT_FUNCS)

    # 3. Modify airoha_qdma_fill_rx_queue: XDP headroom
    i = find_line(lines, 'e->dma_len = SKB_WITH_OVERHEAD(q->buf_size);')
    lines[i] = lines[i].replace(
        'e->dma_len = SKB_WITH_OVERHEAD(q->buf_size);',
        'e->dma_len = SKB_WITH_OVERHEAD(q->buf_size) - AIROHA_XDP_HEADROOM;')

    i = find_line(lines, 'WRITE_ONCE(desc->addr, cpu_to_le32(e->dma_addr));')
    lines[i] = lines[i].replace(
        'cpu_to_le32(e->dma_addr)',
        'cpu_to_le32(e->dma_addr + AIROHA_XDP_HEADROOM)')

    # 4. Insert XDP TX + LRO helpers after airoha_qdma_get_gdm_port
    i = find_line(lines, 'static int airoha_qdma_get_gdm_port')
    end = find_func_end(lines, i)
    insert_after(lines, end, XDP_TX_AND_HELPERS)

    # 5. Modify airoha_qdma_rx_process: add vars, XDP path, metadata, DSCP, LRO
    i = find_line(lines, 'static int airoha_qdma_rx_process(')
    # Add lro_queue and xdp_flush vars after "int done = 0;"
    j = find_line(lines, 'int done = 0;', i)
    insert_after(lines, j, '\tbool lro_queue = airoha_qdma_is_lro_rx_queue(q, q->qdma);\n\tbool xdp_flush = false;')

    # Modify dma_sync size
    j = find_line(lines, 'SKB_WITH_OVERHEAD(q->buf_size), dir);', i)
    lines[j] = lines[j].replace(
        'SKB_WITH_OVERHEAD(q->buf_size), dir);',
        'SKB_WITH_OVERHEAD(q->buf_size) - AIROHA_XDP_HEADROOM, dir);')

    # After "port = eth->ports[p];", insert XDP processing before the skb build
    j = find_line(lines, 'port = eth->ports[p];', i)
    xdp_rx = """\t\t/* XDP processing - only for first fragment */
\t\tif (!q->skb) {
\t\t\tstruct bpf_prog *xdp_prog;

\t\t\trcu_read_lock();
\t\t\txdp_prog = rcu_dereference(port->xdp_prog);
\t\t\tif (xdp_prog) {
\t\t\t\tstruct xdp_buff xdp;
\t\t\t\tu32 act;

\t\t\t\txdp_init_buff(&xdp, q->buf_size, &q->xdp_rxq);
\t\t\t\txdp_prepare_buff(&xdp, e->buf, AIROHA_XDP_HEADROOM,
\t\t\t\t\t\t len, false);

\t\t\t\tact = bpf_prog_run_xdp(xdp_prog, &xdp);
\t\t\t\tswitch (act) {
\t\t\t\tcase XDP_PASS:
\t\t\t\t\tbreak;
\t\t\t\tcase XDP_TX:
\t\t\t\t\tif (airoha_xdp_tx(qdma, &xdp))
\t\t\t\t\t\tpage_pool_recycle_direct(q->page_pool,
\t\t\t\t\t\t\t\t\t virt_to_page(e->buf));
\t\t\t\t\trcu_read_unlock();
\t\t\t\t\tcontinue;
\t\t\t\tcase XDP_REDIRECT:
\t\t\t\t\tif (!xdp_do_redirect(port->dev, &xdp, xdp_prog))
\t\t\t\t\t\txdp_flush = true;
\t\t\t\t\tpage_pool_recycle_direct(q->page_pool,
\t\t\t\t\t\t\t\t virt_to_page(e->buf));
\t\t\t\t\trcu_read_unlock();
\t\t\t\t\tcontinue;
\t\t\t\tdefault:
\t\t\t\t\tbpf_warn_invalid_xdp_action(port->dev, xdp_prog, act);
\t\t\t\t\tfallthrough;
\t\t\t\tcase XDP_DROP:
\t\t\t\t\tpage_pool_recycle_direct(q->page_pool,
\t\t\t\t\t\t\t\t virt_to_page(e->buf));
\t\t\t\t\trcu_read_unlock();
\t\t\t\t\tcontinue;
\t\t\t\t}
\t\t\t}
\t\t\trcu_read_unlock();
\t\t}"""
    insert_after(lines, j, xdp_rx)

    # After napi_build_skb, add skb_reserve for XDP headroom
    j = find_line(lines, 'q->skb = napi_build_skb(e->buf, q->buf_size);', i)
    # Find the "if (!q->skb)" + "goto free_frag;" that follows
    k = find_line(lines, 'goto free_frag;', j)
    insert_after(lines, k, '\n\t\t\tskb_reserve(q->skb, AIROHA_XDP_HEADROOM);')

    # Before eth_type_trans, insert metadata + DSCP + LRO
    j = find_line(lines, 'q->skb->protocol = eth_type_trans', i)
    meta_dscp_lro = """\t\t\t/* Copy XDP metadata mark to skb->mark */
\t\t\t{
\t\t\t\tunsigned char *meta_ptr = q->skb->data - 64;
\t\t\t\tif (meta_ptr >= q->skb->head) {
\t\t\t\t\tu32 magic = get_unaligned_le32(meta_ptr);
\t\t\t\t\tif (magic == 0xA1B2C3D4)
\t\t\t\t\t\tq->skb->mark = get_unaligned_le32(meta_ptr + 4);
\t\t\t\t}
\t\t\t}

\t\t\t/* Derive skb->priority from IP DSCP for queue selection */
\t\t\t{
\t\t\t\tstruct ethhdr *eh = (struct ethhdr *)q->skb->data;
\t\t\t\tif (ntohs(eh->h_proto) == ETH_P_IP) {
\t\t\t\t\tstruct iphdr *iph = (struct iphdr *)(eh + 1);
\t\t\t\t\tif ((unsigned char *)(iph + 1) <= skb_tail_pointer(q->skb))
\t\t\t\t\t\tq->skb->priority = iph->tos >> 5;
\t\t\t\t} else if (ntohs(eh->h_proto) == ETH_P_IPV6) {
\t\t\t\t\tstruct ipv6hdr *ip6h = (struct ipv6hdr *)(eh + 1);
\t\t\t\t\tif ((unsigned char *)(ip6h + 1) <= skb_tail_pointer(q->skb))
\t\t\t\t\t\tq->skb->priority = ipv6_get_dsfield(ip6h) >> 5;
\t\t\t\t}
\t\t\t}

\t\t\tif (lro_queue && (port->dev->features & NETIF_F_LRO) &&
\t\t\t    airoha_qdma_lro_rx_process(q, desc) < 0)
\t\t\t\tgoto free_frag;
"""
    # Insert BEFORE eth_type_trans
    for line_text in reversed(meta_dscp_lro.split('\n')):
        lines.insert(j, line_text + '\n')

    # After airoha_qdma_fill_rx_queue(q), add xdp_flush
    j = find_line(lines, 'airoha_qdma_fill_rx_queue(q);')
    # Find next "return done;"
    k = find_line(lines, 'return done;', j)
    lines.insert(k, '\n\tif (xdp_flush)\n\t\txdp_do_flush();\n\n')

    # 6. Refactor airoha_qdma_init_rx_queue: insert init_rx_pp before it
    i = find_line(lines, 'static int airoha_qdma_init_rx_queue(')
    # Insert init_rx_pp function BEFORE init_rx_queue
    for line_text in reversed(INIT_RX_PP.split('\n')):
        lines.insert(i, line_text + '\n')

    # Now modify init_rx_queue: remove inline page_pool_params,
    # replace with call to init_rx_pp after netif_napi_add
    # Find the page_pool_params block
    j = find_line(lines, 'const struct page_pool_params pp_params', i)
    k = find_line(lines, '};', j)  # end of pp_params
    # Remove pp_params block
    del lines[j:k+1]

    # Remove buf_size assignment
    j2 = find_line(lines, 'q->buf_size = PAGE_SIZE / 2;', i)
    del lines[j2]

    # Remove page_pool_create block
    j3 = find_line(lines, 'q->page_pool = page_pool_create(&pp_params);', i)
    k3 = j3
    # Find the closing } of the error handling
    depth = 0
    while k3 < len(lines):
        if 'return err;' in lines[k3]:
            k3 += 1  # include the return
            if lines[k3].strip() == '}':
                k3 += 1  # include the }
            break
        k3 += 1
    del lines[j3:k3]

    # After netif_napi_add, insert LRO-aware init
    j4 = find_line(lines, 'netif_napi_add(', i)
    init_block = """
\tlro_queue = airoha_qdma_is_lro_rx_queue(q, qdma);
\terr = airoha_qdma_init_rx_pp(q, lro_queue);
\tif (err)
\t\treturn err;

\tif (xdp_rxq_info_reg(&q->xdp_rxq, eth->napi_dev, qid, q->napi.napi_id))
\t\treturn -ENOMEM;
\tif (xdp_rxq_info_reg_mem_model(&q->xdp_rxq, MEM_TYPE_PAGE_POOL, q->page_pool))
\t\treturn -ENOMEM;
"""
    insert_after(lines, j4, init_block)

    # Add bool lro_queue and int err to init_rx_queue locals
    j5 = find_line(lines, 'dma_addr_t dma_addr;', i)
    insert_after(lines, j5, '\tbool lro_queue;\n\tint err;')

    # 7. Insert rx_queue_deinit after cleanup_rx_queue
    i = find_line(lines, 'static void airoha_qdma_cleanup_rx_queue(')
    end = find_func_end(lines, i)
    insert_after(lines, end, RX_QUEUE_DEINIT)

    # 8. In airoha_hw_cleanup, replace cleanup_rx_queue + page_pool with deinit
    i = find_line(lines, 'airoha_qdma_cleanup_rx_queue(&qdma->q_rx[i]);')
    # Delete from this line through page_pool_destroy + closing }
    j = i
    while j < len(lines):
        if 'page_pool_destroy' in lines[j]:
            # Find the closing } after it
            while j < len(lines) and lines[j].strip() != '}':
                j += 1
            j += 1  # include }
            break
        j += 1
    lines[i:j] = ['\t\tairoha_qdma_rx_queue_deinit(&qdma->q_rx[i]);\n']

    # 9. Insert set_features + XDP funcs before airoha_netdev_ops
    i = find_line(lines, 'static const struct net_device_ops airoha_netdev_ops')
    for block in [XDP_SETUP_FUNCS, SET_FEATURES_FUNC]:
        for line_text in reversed(block.split('\n')):
            lines.insert(i, line_text + '\n')

    # 10. Add ndo callbacks to netdev_ops
    i = find_line(lines, '.ndo_select_queue')
    insert_after(lines, i, '\t.ndo_set_features\t= airoha_dev_set_features,')

    i = find_line(lines, '.ndo_setup_tc')
    insert_after(lines, i, '\t.ndo_bpf\t\t= airoha_dev_bpf,\n\t.ndo_xdp_xmit\t\t= airoha_dev_xdp_xmit,')

    # 11. Replace hw_features
    i = find_line(lines, 'dev->hw_features = NETIF_F_IP_CSUM')
    # Delete old hw_features lines (4 lines)
    j = i
    while j < len(lines) and 'dev->dev.of_node' not in lines[j]:
        j += 1
    lines[i:j] = [
        '\tdev->hw_features = AIROHA_HW_FEATURES | NETIF_F_LRO;\n',
        '\tdev->features |= AIROHA_HW_FEATURES;\n',
        '\tdev->vlan_features = AIROHA_HW_FEATURES;\n',
    ]

    with open(f'{POSTDIR}/airoha_eth.c', 'w') as f:
        f.writelines(lines)
    print(f'airoha_eth.c: {len(lines)} lines')


def patch_eth_h():
    with open(f'{PREDIR}/airoha_eth.h') as f:
        lines = f.readlines()

    # 1. Add BPF includes after reset.h
    i = find_line(lines, '<linux/reset.h>')
    insert_after(lines, i, '#include <linux/bpf.h>\n#include <net/xdp.h>')

    # 2. Add XDP/LRO defines after PPE_ENTRY_SIZE
    i = find_line(lines, '#define PPE_ENTRY_SIZE')
    insert_after(lines, i, ETH_H_DEFINES)

    # 3. Add xdp_rxq_info to struct airoha_queue (after page_pool)
    i = find_line(lines, 'struct page_pool *page_pool;')
    insert_after(lines, i, '\tstruct xdp_rxq_info xdp_rxq;')

    # 4. Add xdp_prog to airoha_gdm_port (after "int id;")
    i = find_line(lines, '\tint id;')
    insert_after(lines, i, '\n\tstruct bpf_prog __rcu *xdp_prog;')

    with open(f'{POSTDIR}/airoha_eth.h', 'w') as f:
        f.writelines(lines)
    print(f'airoha_eth.h: {len(lines)} lines')


def patch_ppe_c():
    with open(f'{PREDIR}/airoha_ppe.c') as f:
        lines = f.readlines()

    # 1. Add dscp_to_queue after ppe_lock
    i = find_line(lines, 'static DEFINE_SPINLOCK(ppe_lock);')
    insert_after(lines, i, DSCP_TO_QUEUE)

    # 2. Add FOE QoS before kzalloc in flow_offload_replace
    i = find_line(lines, 'e = kzalloc(sizeof(*e), GFP_KERNEL);')
    foe_qos = """\t/* Populate hardware QoS fields from flow DSCP */
\tif (offload_type != PPE_PKT_TYPE_BRIDGE &&
\t    flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IP)) {
\t\tstruct flow_match_ip match_ip;
\t\tu8 dscp, ch, q;
\t\tu32 *foe_data, *foe_ib2;

\t\tflow_rule_match_ip(rule, &match_ip);
\t\tdscp = match_ip.key->tos >> 2;

\t\tairoha_dscp_to_queue(dscp, &ch, &q);

\t\tif (offload_type >= PPE_PKT_TYPE_IPV6_ROUTE_3T) {
\t\t\tfoe_data = &hwe.ipv6.data;
\t\t\tfoe_ib2 = &hwe.ipv6.ib2;
\t\t} else {
\t\t\tfoe_data = &hwe.ipv4.data;
\t\t\tfoe_ib2 = &hwe.ipv4.ib2;
\t\t}

\t\t*foe_ib2 &= ~AIROHA_FOE_IB2_DSCP;
\t\t*foe_ib2 |= FIELD_PREP(AIROHA_FOE_IB2_DSCP, dscp);

\t\t*foe_data &= ~(AIROHA_FOE_CHANNEL | AIROHA_FOE_QID);
\t\t*foe_data |= FIELD_PREP(AIROHA_FOE_CHANNEL, ch) |
\t\t\t     FIELD_PREP(AIROHA_FOE_QID, q);
\t}

"""
    for line_text in reversed(foe_qos.split('\n')):
        lines.insert(i, line_text + '\n')

    with open(f'{POSTDIR}/airoha_ppe.c', 'w') as f:
        f.writelines(lines)
    print(f'airoha_ppe.c: {len(lines)} lines')


def patch_regs_h():
    with open(f'{PREDIR}/airoha_regs.h') as f:
        lines = f.readlines()

    # 1. Add LRO registers after CDM_CRSN_QSEL_REASON_MASK
    i = find_line(lines, 'CDM_CRSN_QSEL_REASON_MASK')
    insert_after(lines, i, LRO_REGS)

    # 2. Add RX MSG masks after RXMSG_PPE_ENTRY_MASK
    i = find_line(lines, 'QDMA_ETH_RXMSG_PPE_ENTRY_MASK')
    insert_after(lines, i, RX_MSG_MASKS)

    with open(f'{POSTDIR}/airoha_regs.h', 'w') as f:
        f.writelines(lines)
    print(f'airoha_regs.h: {len(lines)} lines')


def generate_diff():
    """Generate unified diff between pre and post."""
    result = []
    for f in ['airoha_eth.c', 'airoha_eth.h', 'airoha_ppe.c', 'airoha_regs.h']:
        r = subprocess.run(
            ['diff', '-U5', f'{PREDIR}/{f}', f'{POSTDIR}/{f}'],
            capture_output=True, text=True)
        diff = r.stdout
        diff = diff.replace(PREDIR + '/', 'a/drivers/net/ethernet/airoha/')
        diff = diff.replace(POSTDIR + '/', 'b/drivers/net/ethernet/airoha/')
        # Strip timestamps from --- and +++ lines
        import re
        diff = re.sub(r'^(---\s+\S+)\t.*$', r'\1', diff, flags=re.MULTILINE)
        diff = re.sub(r'^(\+\+\+\s+\S+)\t.*$', r'\1', diff, flags=re.MULTILINE)
        result.append(diff)
    return '\n'.join(result)


def write_patch(diff):
    header = """From: Joel Wiramu Pauling <aenertia@aenertia.net>
Date: Thu, 03 Apr 2026 12:00:00 +1300
Subject: [PATCH] net: airoha: Add XDP, TCP LRO, and hybrid QoS support

Add XDP (eXpress Data Path) support for the Airoha AN7581 ethernet
driver, enabling high-performance packet processing with eBPF programs.
Also adds TCP hardware Large Receive Offload (LRO) and DSCP-based
hardware QoS queue mapping.

Rewritten from scratch for kernel 6.18 linked-list TX descriptor model.

XDP features:
- XDP_PASS, XDP_TX, XDP_REDIRECT, XDP_DROP actions
- ndo_bpf and ndo_xdp_xmit callbacks
- Uses xdp_convert_buff_to_frame for safe TX DMA lifecycle
- Batch lock for ndo_xdp_xmit (single doorbell write)
- XDP metadata mark passthrough (64-byte airoha_meta struct)

LRO features:
- Hardware TCP LRO with 8 aggregation queues
- LRO-aware page pool sizing (order-2 pages)
- ndo_set_features toggle with QDMA quiesce/reinit
- IPv4/IPv6 header fixup, TCP ACK/window/timestamp coalescing

QoS (ADR-001):
- DSCP-to-queue mapping in PPE FOE entries
- 4 channels (bulk/normal/interactive/realtime) x 8 queues

Signed-off-by: Joel Wiramu Pauling <aenertia@aenertia.net>
Co-developed-by: Lorenzo Bianconi <lorenzo@kernel.org>
---

"""
    with open(OUTPATCH, 'w') as f:
        f.write(header + diff + '\n')
    lines = sum(1 for _ in open(OUTPATCH))
    print(f'Patch written: {OUTPATCH} ({lines} lines)')


if __name__ == '__main__':
    print('Applying changes to airoha driver for 6.18...')
    # Copy pre to post
    for f in ['airoha_eth.c', 'airoha_eth.h', 'airoha_ppe.c', 'airoha_regs.h']:
        import shutil
        shutil.copy2(f'{PREDIR}/{f}', f'{POSTDIR}/{f}')

    patch_regs_h()
    patch_eth_h()
    patch_ppe_c()
    patch_eth_c()

    diff = generate_diff()
    write_patch(diff)
    print('Done!')
