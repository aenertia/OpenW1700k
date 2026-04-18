# ADR-001: eBPF Soft Hook Architecture for Airoha AN7581

**Status:** Accepted
**Date:** 2026-03-29
**Author:** Joel Wirāmu Pauling <aenertia@aenertia.net>

## Context

The Airoha AN7581 SoC (used in the W1700K platform) contains a hardware NPU
with a Packet Processing Engine (PPE) capable of L2/L3/L4 flow offload via
a Flow Offload Engine (FOE) table. The upstream kernel driver is split across
three source files:

- `airoha_eth.c` — Ethernet MAC, DMA rings, GDM port management
- `airoha_ppe.c` — PPE/FOE table management, flow entry lifecycle, stats
- `airoha_npu.c` — NPU firmware interface and flow programming

The kernel's `nft_flow_offload` infrastructure already handles L2 bridge
offload and L3/L4 NAT offload by programming the PPE/FOE table through the
standard `ndo_setup_tc` callback path. This works and is the primary
production offload mechanism.

However, the kernel flowtable path has limited visibility: conntrack counters
are not updated for hardware-offloaded flows (the hardware handles packets
entirely in silicon), and there is no easy mechanism to observe flow
classification decisions or enrich metadata for downstream consumers.

We need a mechanism that:

1. Observes ingress traffic and classifies flows (FIB + FDB lookup)
2. Provides telemetry from the hardware PPE stats back to conntrack
3. Coexists with (not replaces) the kernel's native HWNAT offload path
4. Runs on an embedded target with limited resources (128MB RAM typical)

## Decision

We adopt an **eBPF Soft Hook** architecture with three components:

1. **XDP ingress classifier** (`airoha_hybrid_offload.c`) — Attaches to
   physical interfaces, parses packet headers, performs FIB lookup and FDB
   lookup (from daemon-populated maps), prepends metadata via
   `bpf_xdp_adjust_meta()`, and submits flow keys to a ring buffer for
   daemon processing. Always returns `XDP_PASS` — this is an observer, not
   a filter or redirector. No conntrack lookup in BPF (avoids CO-RE/vmlinux.h
   dependency).

2. **Userspace sync daemon** (`airoha-sync-daemon`) — Multi-threaded C
   daemon that:
   - Consumes flow events from the XDP ring buffer
   - Polls PPE debugfs (`/sys/kernel/debug/ppe{0,1}/bind`) to read
     hardware flow stats
   - Computes counter deltas and syncs them back to conntrack via
     libnetfilter_conntrack
   - Maintains L2 FDB and bridge topology maps via netlink listener
   - Garbage-collects stale internal flow entries

3. **Telemetry placeholder** (`airoha_telemetry.c`) — Reserved for future
   kprobe-based real-time telemetry on `airoha_ppe_foe_entry_get_stats`.
   Currently unused; the daemon polls debugfs instead.

### Key Design Principle

The eBPF layer acts as an **observer and classifier**. The kernel flowtable
(`nft_flow_offload`) handles actual NPU programming. Both `flow_offloading`
and `flow_offloading_hw` are enabled in the firewall config. The eBPF
program never drops, redirects, or modifies packets.

```
                         DATA FLOW
                         =========

  ┌─────────┐     ┌──────────────────────┐     ┌─────────────┐
  │ Physical │────>│   XDP Program        │────>│ Linux       │
  │ NIC      │     │ (observer only)      │     │ Network     │
  │ wan/lan* │     │                      │     │ Stack       │
  └─────────┘     │ • Parse L2/L3/L4     │     │             │
                  │ • FIB lookup         │     │ conntrack   │
                  │ • FDB lookup (map)   │     │ nft_flow_   │
                  │ • Set XDP metadata   │     │  offload    │
                  │ • Submit flow key    │     └──────┬──────┘
                  │   to ring buffer     │            │
                  │ • XDP_PASS always    │            │ programs
                  └──────────┬───────────┘            │ PPE/FOE
                             │                        │
                    flow key │                        v
                             │              ┌─────────────────┐
                             v              │   Airoha NPU    │
                  ┌────────────────────┐    │   (Hardware)    │
                  │  Sync Daemon       │    │                 │
                  │                    │    │ FOE Table       │
                  │ • Ring buf consumer│    │ L2/L3/L4 offload│
                  │ • debugfs poller   │───>│                 │
                  │   (PPE stats)      │    └─────────────────┘
                  │ • conntrack sync   │         reads stats
                  │ • FDB/bridge maps  │         via debugfs
                  │ • orphan GC        │
                  └────────────────────┘

  Maps (BPF, pinned at /sys/fs/bpf/):
  ┌─────────────────────┐  ┌──────────────────────┐
  │ iface_offload_map   │  │ mac_fdb_map          │
  │ ifindex -> cap      │  │ (mac,bridge) -> port │
  └─────────────────────┘  └──────────────────────┘
  ┌─────────────────────┐  ┌──────────────────────┐
  │ port_to_bridge_map  │  │ flow_event_rb        │
  │ port -> bridge      │  │ ring buffer (256KB)  │
  └─────────────────────┘  └──────────────────────┘
```

## Dependencies

### Kernel Configuration

```
CONFIG_DEBUG_INFO_BTF=y       # BTF type info (future kprobe use)
CONFIG_KPROBES=y              # kprobe support (future telemetry)
CONFIG_BPF_SYSCALL=y          # BPF syscall
CONFIG_BPF_JIT=y              # JIT for BPF on ARM64
CONFIG_XDP_SOCKETS=y          # XDP support
CONFIG_NET_CLS_BPF=y          # BPF classifier
CONFIG_DEBUG_FS=y             # debugfs for PPE stats
```

### Build Dependencies

- `bpf-headers` — OpenWrt package providing kernel headers for BPF
  compilation (used via `$(call CompileBPF,...)` in the Makefile)
- `libbpf` — Userspace BPF library for map access and ring buffer
- `libnetfilter-conntrack` — Conntrack manipulation
- `libmnl` — Netlink message handling
- `ip-full` — `ip` command with XDP support for program attachment

### Runtime

- Kernel must expose `/sys/kernel/debug/ppe0/bind` and
  `/sys/kernel/debug/ppe1/bind` (standard airoha_ppe.c debugfs)
- BPF filesystem mounted at `/sys/fs/bpf/`

## Consequences

### Benefits

- **No kernel patches required** for basic operation — debugfs polling
  works with unmodified upstream airoha driver
- **Coexists with kernel HWNAT** — does not fight over FOE table ownership
- **No CO-RE dependency** — avoids vmlinux.h generation, works with
  OpenWrt's standard bpf-headers infrastructure
- **Observable** — flow classification visible from userspace via ring buffer
- **Incremental** — kprobe telemetry can be added later without changing
  the architecture

### Trade-offs

- **Polling latency** — debugfs stats are polled (5s default), not streamed
  in real-time. Conntrack counters may lag behind actual hardware counters.
- **debugfs dependency** — relies on kernel debugfs interface which is not
  a stable ABI. Format changes in airoha_ppe.c debugfs output will break
  the parser.
- **XDP metadata unused** — the metadata prepended by the XDP program is
  currently not consumed by any downstream BPF program or driver hook. It
  exists for future use (e.g., TC ingress classifier).
- **Per-packet BPF overhead** — every ingress packet traverses the XDP
  program even though we always pass. On a 2.5G link this is ~3.7Mpps
  worst case. The XDP program is lightweight (FIB lookup + map lookups)
  but not zero cost.
- **Duplicate classification** — the XDP program classifies flows that the
  kernel flowtable will also classify independently. This is intentional
  (observer model) but means some work is done twice.

---

## Phase 2: Hybrid QoS — Hardware Offload with Software AQM Control

**Status:** Accepted
**Date:** 2026-03-29
**Supersedes:** Trade-off "XDP metadata unused" from Phase 1

### Problem

Phase 1 established the XDP observer and sync daemon, but left a critical
gap: SQM/AQM and NPU hardware offload are mutually exclusive per flow.

When `nft_flow_offload` pushes a flow to the PPE/FOE table, that flow
bypasses the entire Linux network stack — no qdisc, no fq_codel, no AQM
of any kind. The hardware forwards packets in silicon at line rate with
zero CPU involvement. This is desirable for bulk throughput but eliminates
bufferbloat protection and latency management for those flows.

The Phase 1 XDP observer prepends `struct airoha_meta` with a
classification mark (`0xAF00`) and flow metadata via `bpf_xdp_adjust_meta()`.
However, this metadata was never consumed — it sat in the SKB headroom
unused. The mark never reached `skb->mark`, so standard nftables rules
(`meta mark`) and tc filters (`fw`) could not see it. The offload decision
in `nft_flow_offload` had no mark-based gating — every qualifying flow was
offloaded unconditionally.

Additionally, the FOE entry has hardware QoS fields (`CHANNEL`, `QID`,
`SHAPER_ID`, `IB2_DSCP`) that are defined in silicon but never populated
by the driver — all left at defaults (channel=0, qid=0, shaper=0x7f). The
QDMA has 4 channels x 8 queues = 32 hardware queues with ETS scheduling
already implemented via `TC_SETUP_QDISC_ETS`, but every offloaded flow
lands in queue 0.

### Decision

We extend the architecture with a **mark-based offload gate** that allows
standard userspace tooling (nftables, tc, SQM scripts) to control which
flows are hardware-offloaded and which remain on the CPU path for software
AQM.

The design has four components:

1. **XDP DSCP classifier** — the existing XDP observer is extended to
   extract DSCP (IPv4 TOS byte / IPv6 Traffic Class field) and look up a
   daemon-populated BPF map (`dscp_class_map`) to determine a
   classification mark. The mark encodes the offload decision:

   | Mark | Class | Action |
   |------|-------|--------|
   | `0xAF01` | Bulk (CS1, AF1x) | Offload to NPU |
   | `0xAF02` | Normal (CS0, AF2x, AF3x) | Offload to NPU |
   | `0xAF03` | Interactive (CS4, AF4x, EF) | Keep on CPU — fq_codel AQM |
   | `0xAF04` | Realtime (CS6, CS7) | Keep on CPU — fq_codel AQM |

   The `dscp_class_map` is a BPF hash map populated by the daemon at
   startup from configuration. The daemon can update it at runtime
   (SIGHUP) without reloading the XDP program.

2. **Driver meta-to-SKB bridge** — a small patch to `airoha_eth.c` in the
   RX path. After `napi_build_skb()` following `XDP_PASS`, the driver
   checks if `data_meta` contains a valid `airoha_meta` (magic
   `0xA1B2C3D4`) and copies `meta->mark` to `skb->mark`. It also derives
   `skb->priority` from the IP DSCP field for hardware queue selection
   via `ndo_select_queue()`.

   This makes the XDP classification mark visible to:
   - `nft meta mark` — nftables rules
   - `tc filter ... fw` — tc firewall classifier
   - SQM scripts — via standard mark-based classification
   - Any userspace tool that reads `skb->mark`

3. **nftables mark-gated offload** — firewall rules that gate the
   `flow offload @ft` decision on `meta mark`:

   ```nft
   chain forward {
     type filter hook forward priority 0;
     # Offload bulk + normal (marks 0xAF01, 0xAF02)
     meta mark & 0xFF00 == 0xAF00 meta mark & 0x00FF <= 0x02 flow offload @ft
     # Interactive + realtime stay on CPU for AQM
   }
   ```

   Users can override classification with standard nft rules:
   ```nft
   # Force all traffic to 10.0.0.50 through fq_codel AQM
   ip daddr 10.0.0.50 meta mark set 0xAF03
   ```

4. **FOE QoS population** — when the PPE programs a FOE entry for an
   offloaded flow, the driver reads the DSCP from the flow tuple and
   sets hardware QoS fields:

   - `AIROHA_FOE_CHANNEL` (5 bits) — selects QDMA TX channel (0-3)
   - `AIROHA_FOE_QID` (3 bits) — selects queue within channel (0-7)
   - `AIROHA_FOE_IB2_DSCP` (8 bits) — preserves DSCP in forwarded packets
   - `AIROHA_FOE_SHAPER_ID` (8 bits) — per-class rate limiter (optional)

   The QDMA hardware provides 4 channels x 8 queues = 32 queues with
   ETS scheduling (strict priority + weighted round-robin), configured
   via the existing `TC_SETUP_QDISC_ETS` offload.

### Dynamic Reclassification

Flows are not permanently locked into their initial classification. The
daemon can trigger reclassification by deleting the conntrack entry:

```
daemon: nfct_query(NFCT_Q_DESTROY, ct)
  → IPS_DYING_BIT set on conntrack
    → flow table GC (1s cycle) detects dying CT
      → FLOW_CLS_DESTROY → airoha_ppe_foe_remove_flow()
        → FOE entry set to INVALID in hardware
          → next packet hits CPU slow path
            → XDP observer reclassifies (reads dscp_class_map)
              → driver copies new mark to skb->mark
                → nft rules re-evaluate → offload or keep on CPU
```

Latency: 1-3 seconds from daemon decision to flow returning to CPU path.

The sync daemon already has the `NFCT_Q_DESTROY` capability (used in
`sync_hardware_counters()` with `destroy=1`). The reclassification worker
extends this with policy triggers:

- **DSCP change detected** — upstream remark detected via PPE stats
- **Congestion on hardware queue** — QDMA queue depth exceeds threshold
- **Policy update** — daemon updates `dscp_class_map`, then tears down
  affected flows so they re-enter with new classification
- **User request** — `conntrack -D` from CLI has the same effect

### Qdisc Architecture

#### Decision: `mq` + `fq_codel`, not CAKE

The default qdisc for forwarding interfaces is `mq` (multi-queue) root
with `fq_codel` leaves. This is already active — the kernel auto-attaches
it because the Airoha QDMA exposes 32 TX queues with BQL support.

**Why not CAKE:**

- CAKE's integrated shaper is unnecessary — bulk traffic is hardware-
  offloaded; the CPU path only sees interactive flows that don't need
  rate limiting
- CAKE takes a single global qdisc lock, destroying the 32-queue
  parallelism that `mq` + per-queue `fq_codel` provides
- CAKE is ~15% more CPU-intensive per packet than fq_codel (OpenWrt wiki)
- CAKE is available via `luci-app-sqm` if a user explicitly wants it on
  a specific interface; standard SQM tooling remains fully functional

**`fq_codel` provides:**

- Per-flow fair queuing (flow isolation via hash, 1024 buckets)
- CoDel AQM per flow (5ms target latency, drop/mark signaling)
- Per-queue parallelism via `mq` (zero cross-core lock contention)
- Already built-in (`CONFIG_NET_SCH_FQ_CODEL=y`), zero config needed

**`fq` for BBR pacing:**

The `fq` (Fair Queuing) qdisc is additionally enabled for BBR's pacing
support on router-originated traffic. BBR sets per-socket pacing rates
via `sk->sk_pacing_rate`, and `fq` enforces them via EDT (Earliest
Departure Time) scheduling. Without `fq`, BBR degrades to cwnd-limited
mode. `fq` is bound where router-originated traffic egresses; forwarded
traffic uses `mq` + `fq_codel`.

#### SQM Compatibility

Standard SQM scripts (`luci-app-sqm`) work without modification:

- CAKE-based scripts (`layer_cake.qos`, `piece_of_cake.qos`) can be
  attached by the user; they replace `mq` root with CAKE
- fq_codel-based scripts work natively with the existing setup
- CAKE reads DSCP directly from IPv4 TOS / IPv6 Traffic Class; it does
  not depend on `skb->mark` or `skb->priority` for tin selection
- `act_ctinfo` + `act_connmark` are available for DSCP restoration
  through NAT on the CPU path

### TCP Congestion Control: BBR

BBR (v1, kernel 6.12 mainline) is set as the default TCP congestion
control. This affects router-originated connections only (SSH, DNS,
speedtest, VPN tunnels). Forwarded traffic uses the sender's CC.

BBR + `fq` provides pacing for router-originated TCP. For forwarded
traffic, `mq` + `fq_codel` provides AQM independently of sender CC.

### CPU / Power Management: schedutil + uclamp + cgroup v2

#### Governor: schedutil (replaces ondemand)

`schedutil` uses the scheduler's PELT (Per-Entity Load Tracking) signals
to set CPU frequency at context-switch time, rather than ondemand's
timer-based sampling. Sub-millisecond frequency response vs. ondemand's
~10ms sampling interval.

The AN7581 has 15 OPP steps from 500 MHz to 1200 MHz (50 MHz increments),
managed by ARM SMCCC firmware (AVS). All 4 A53 cores share a single
frequency domain (opp-shared).

#### Utilization Clamping: uclamp via cgroup v2

procd mounts cgroup2 at `/sys/fs/cgroup` automatically at early boot
(`early.c:64`). No systemd required. The v1 controllers are compiled out
(`CPUSETS_V1=n`, `MEMCG_V1=n`).

`uclamp.min` on network processing tasks guarantees a minimum CPU
frequency during packet bursts without locking to a fixed frequency:

| cgroup | uclamp.min | uclamp.max | Effect |
|--------|------------|------------|--------|
| `/sys/fs/cgroup/netdev` | 600 (~59%) | 1024 (100%) | Floor ~800 MHz for NAPI/IRQ |
| `/sys/fs/cgroup/system` | 0 (0%) | 768 (~75%) | Cap at ~900 MHz for background |

#### CPU Idle: TEO

TEO (Timer Events Oriented) idle governor for C-state selection. The
AN7581 DTS defines only WFI (mandatory ARM idle state), so TEO's benefit
is marginal. Positions the system correctly if deeper states are added.

### 10G Edge Gateway Sysctl Tuning

Tuned for XGS-PON WAN (10G symmetric, ~1-5ms RTT to OLT) and 10G LAN
downlink, with ~342MB available RAM (512MB physical minus 170MB NPU/QDMA
reserved). See `base-files/etc/sysctl.d/20-w1700k-10g-gateway.conf`.

### Architecture Diagram

```
  Ingress (WAN 10G / LAN 10G)
       │
  ┌────┴─────────────────────────────┐
  │ XDP Observer (airoha_classify)   │
  │                                  │
  │ • Parse L2/L3/L4 (v4 + v6)      │
  │ • Extract DSCP (TOS / TC field)  │
  │ • Lookup dscp_class_map (BPF)    │
  │ • Prepend airoha_meta:           │
  │   - magic = 0xA1B2C3D4           │
  │   - mark = 0xAF01..04            │
  │ • Submit flow_event to ring buf  │
  │ • XDP_PASS (always)              │
  └────┬─────────────────────────────┘
       │
  ┌────┴─────────────────────────────┐
  │ Driver RX (airoha_eth.c)         │
  │                                  │
  │ napi_build_skb()                 │
  │ if data_meta magic == 0xA1B2C3D4:│
  │   skb->mark = meta->mark         │
  │   skb->priority from IP DSCP     │
  └────┬─────────────────────────────┘
       │
  ┌────┴─────────────────────────────┐
  │ nftables forward chain           │
  │                                  │
  │ mark 0xAF01/02 → flow offload   │
  │ mark 0xAF03/04 → accept (CPU)   │
  │ user rules can override marks    │
  └────┬──────────────┬──────────────┘
       │              │
  ┌────┴────┐    ┌────┴──────────────┐
  │ PPE/FOE │    │ mq + fq_codel     │
  │         │    │ (32 TX queues)     │
  │ DSCP →  │    │ per-queue CoDel   │
  │ CHANNEL │    │ AQM + fair queue  │
  │ + QID   │    │ no lock contend   │
  │         │    └────┬──────────────┘
  │ ETS hw  │         │
  │ sched   │         │
  └────┬────┘         │
       │              │
  Egress (WAN TX / LAN TX)

  ┌──────────────────────────────────┐
  │ Sync Daemon                      │
  │                                  │
  │ Threads:                         │
  │ 1. Netlink topology listener     │
  │ 2. Ring buffer consumer          │
  │ 3. debugfs PPE stats poller      │
  │ 4. Orphan GC                     │
  │ 5. Reclassification worker       │
  │                                  │
  │ Reclassification:                │
  │   nfct_query(DESTROY, ct)        │
  │   → FOE torn down in 1-3s       │
  │   → flow returns to XDP+nft      │
  │   → reclassified with new mark   │
  │                                  │
  │ BPF maps (daemon-populated):     │
  │ • dscp_class_map (DSCP → mark)   │
  │ • iface_offload_map              │
  │ • mac_fdb_map / port_to_bridge   │
  │ • flow_event_rb                  │
  └──────────────────────────────────┘

  ┌──────────────────────────────────┐
  │ CPU / Power (cgroup v2)          │
  │                                  │
  │ Governor: schedutil              │
  │ OPP: 500-1200 MHz (15 steps)    │
  │ Idle: TEO (WFI)                 │
  │                                  │
  │ /sys/fs/cgroup/netdev/           │
  │   cpu.uclamp.min = 600          │
  │   → NAPI + IRQ threads          │
  │                                  │
  │ /sys/fs/cgroup/system/           │
  │   cpu.uclamp.max = 768          │
  │   → background tasks            │
  └──────────────────────────────────┘
```

### What This Allows

- Standard `nft meta mark` rules gate hardware offload decisions
- Standard `tc` and SQM scripts work without modification
- `conntrack -D` from CLI reclassifies any flow within 1-3 seconds
- Daemon updates `dscp_class_map` at runtime without XDP reload
- User can override any classification with nft rules
- Hardware ETS provides priority scheduling for offloaded flows
- Full IPv4 and IPv6 support at every layer
- BBR + `fq` pacing for router-originated connections

### What This Does NOT Allow

- CAKE-level per-flow AQM for hardware-offloaded flows (HW has priority
  queues, not fair queues; no CoDel/Cobalt in silicon)
- ECN marking for offloaded flows (HW forwarding doesn't touch TCP flags)
- Sub-second reclassification (conntrack GC runs at 1s intervals)
- Per-packet reclassification of active offloaded flows (must tear down
  FOE entry first)

### Additional Dependencies (Phase 2)

#### Kernel Configuration

```
CONFIG_TCP_CONG_BBR=y                # BBR congestion control
CONFIG_DEFAULT_TCP_CONG="bbr"        # Default CC for router-originated TCP
CONFIG_NET_SCH_FQ=y                  # Fair Queuing qdisc for BBR pacing
CONFIG_CPU_FREQ_GOV_SCHEDUTIL=y      # schedutil governor
CONFIG_CPU_FREQ_DEFAULT_GOV_SCHEDUTIL=y
CONFIG_UCLAMP_TASK=y                 # Per-task utilization clamping
CONFIG_UCLAMP_TASK_GROUP=y           # cgroup-based uclamp
CONFIG_UCLAMP_BUCKETS_COUNT=5        # uclamp bucket granularity
CONFIG_CPU_IDLE=y                    # CPU idle framework
CONFIG_CPU_IDLE_GOV_TEO=y            # TEO idle governor
CONFIG_ARM_PSCI_CPUIDLE=y            # PSCI-based idle states
CONFIG_CPU_FREQ_THERMAL=y            # Thermal-cpufreq integration
```

#### Build Dependencies

- `kmod-sched-ctinfo` — DSCP restoration from conntrack marks
- `kmod-sched-connmark` — connmark save/restore for NAT traversal

### Implementation Files

| File | Change |
|------|--------|
| `ADR-001-ebpf-soft-hook.md` | This document (Phase 2 extension) |
| `airoha_hybrid_offload.c` | DSCP extraction + `dscp_class_map` lookup |
| `999-airoha-eth-xdp-lro-support.patch` | meta→skb->mark in RX path |
| `999-airoha-eth-xdp-lro-support.patch` | FOE CHANNEL/QID/DSCP from flow |
| `airoha-sync-daemon.c` | Reclassification worker + BPF map init |
| `airoha-ebpf.init` | cgroup setup + RPS/RFS + `fq` binding |
| `20-w1700k-10g-gateway.conf` | sysctl tuning for 10G edge gateway |
| `16-w1700k-nft-offload-policy` | Mark-gated nftables offload rules |
| `seed.config` | BBR, fq, ctinfo, connmark packages |
| `an7581/config-6.12` | schedutil, uclamp, TEO, BBR kernel configs |

---

## Phase 3: Hardening & Performance (2026-03-30)

### Changes

Following live device profiling of the Phase 2 build, the following issues
were identified and resolved:

#### Critical Fixes

1. **SSH broken (dropbear "String too long")** — OpenSSH 10 sends long
   KEXINIT proposals including post-quantum algorithms. Dropbear v2025.89's
   default `RECV_MAX_PAYLOAD_LEN` (32KB) is too small to hold the combined
   proposal. Fixed by:
   - Enabling `CONFIG_DROPBEAR_MLKEM768=y` (ML-KEM768 post-quantum KEX)
   - Increasing `RECV_MAX_PAYLOAD_LEN` to 262144 (256KB) in the dropbear
     Makefile's `DB_OPT_COMMON`
   - Adding `RootPasswordAuth 'on'` via UCI defaults

2. **XDP on DSA user ports** — `lan3@eth0` and `lan4@eth0` are DSA soft
   netdevs with no `ndo_bpf` support. XDP fell back to `xdpgeneric` mode,
   which is functionally useless and can corrupt `skb->data_meta` in the
   bridge path. Fixed by restricting XDP attachment to native-capable GDM
   ports only (`wan`, `lan2`).

3. **BPF maps not pinned** — The init script used `ip link set xdp obj`
   which loads the program but does NOT pin maps to `/sys/fs/bpf/`. The
   sync daemon expected pinned maps and crash-looped. Fixed by adding
   `bpftool map pin` after XDP attachment.

4. **Sync daemon crash loop** — Replaced immediate `exit(EXIT_FAILURE)` on
   missing maps with exponential backoff retry (1s→8s, 12 attempts ≈ 68s).

5. **LuCI overview page broken (ORB)** — nginx `_redirect2ssl` used HTTP 302
   (temporary redirect) for port 80→443. Modern browsers' OpaqueResponseBlocking
   blocks 302 responses for `no-cors` subrequests (SVGs, API calls). Changed
   to 301 (permanent, cached) via UCI defaults.

#### Performance

6. **ARM64 Crypto Extensions (CE) entirely disabled** — All AES/SHA/GHASH
   operations were running in generic C code. Cortex-A53 has dedicated CE
   instructions (5–20x faster). Enabled the complete CE suite:
   `AES_ARM64_CE`, `AES_ARM64_CE_BLK`, `AES_ARM64_CE_CCM`,
   `AES_ARM64_NEON_BLK`, `AES_ARM64_BS`, `SHA1_ARM64_CE`,
   `SHA2_ARM64_CE`, `SHA256_ARM64`, `SHA512_ARM64_CE`,
   `GHASH_ARM64_CE`, `POLYVAL_ARM64_CE`, plus `CRYPTO_SIMD` and
   `CRYPTO_CRYPTD` infrastructure.

7. **EIP-93 hardware crypto engine — REVERTED** — Initially enabled
   (`CONFIG_CRYPTO_DEV_EIP93=y`), but live testing revealed a kernel panic
   in `_eip93_hash_init+0x114/0x2d0`: NULL pointer dereference at virtual
   address `0x0000000000000008` when `crypto_ahash_digest()` routes hash
   operations through the EIP-93 driver. The driver was validated on the
   AN7583 sibling SoC, not the AN7581 used in the W1700K. Disabled pending
   upstream driver fix. ARM64 CE software crypto provides equivalent
   performance for all symmetric operations.

#### Memory Management

8. **ZRAM** — Enabled with zstd compression (zstd library already present).
   With 449 packages + podman containers on 2GB RAM, compressed swap provides
   essential memory headroom. `CONFIG_ZSMALLOC=y` for the backing allocator.

9. **KSM** — Enabled for container memory deduplication. Identical pages from
   shared base images merged via COW. Enabled at boot via UCI defaults +
   rc.local persistence.

10. **vm.* sysctls** — Added `vm.swappiness=40`, `vm.vfs_cache_pressure=50`,
    `vm.dirty_ratio=10`, `vm.dirty_background_ratio=5`,
    `vm.min_free_kbytes=16384`, `vm.watermark_scale_factor=50`.

#### Crypto Infrastructure (iwd/PKCS#8 ready)

11. **Asymmetric key subsystem** — Enabled `CONFIG_ASN1`,
    `CONFIG_ASYMMETRIC_KEY_TYPE`, `CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE`,
    `CONFIG_PKCS8_PRIVATE_KEY_PARSER`, `CONFIG_X509_CERTIFICATE_PARSER`,
    `CONFIG_PKCS7_MESSAGE_PARSER`, `CONFIG_CRYPTO_RSA`, `CONFIG_CRYPTO_ECDSA`,
    `CONFIG_CRYPTO_DH`, `CONFIG_KEY_DH_OPERATIONS`, plus `kmod-crypto-user`
    (AF_ALG sockets) and `kmod-crypto-ecdh`. This makes the kernel ready for
    iwd, dm-verity, module signing, and WPA3-Enterprise PKCS#8 keys without
    requiring further kernel changes.

12. **wpad-openssl** — Resolved conflict where `wpad-basic-mbedtls` was
    overriding the seed's `wpad-openssl=y`. Explicitly set
    `CONFIG_PACKAGE_wpad-basic-mbedtls=n` to get full WPA3 (SAE + OWE),
    mesh SAE, FILS, and EAP-TLS.

#### Container Support

13. **cgroup controllers** — Added `CONFIG_KERNEL_CGROUP_FREEZER=y` and
    `CONFIG_KERNEL_CGROUP_DEVICE=y` for full podman `pause`/`unpause` and
    container device access control.

### Implementation Files (Phase 3)

| File | Change |
|------|--------|
| `ADR-001-ebpf-soft-hook.md` | This document (Phase 3 extension) |
| `seed.config` | MLKEM768, wpad-openssl, ZRAM, crypto-user, cgroups |
| `an7581/config-6.12` | ARM64 CE, EIP-93, ASN1/PKCS8, ZRAM, KSM |
| `dropbear/Makefile` | `RECV_MAX_PAYLOAD_LEN=262144` |
| `airoha-ebpf.init` | Remove DSA ports, add BPF map pinning |
| `airoha-sync-daemon.c` | Exponential backoff retry for map discovery |
| `20-w1700k-10g-gateway.conf` | vm.* memory management sysctls |
| `17-w1700k-defaults` | Dropbear auth, nginx 301, KSM enablement |

---

## Phase 4: OpenSSH + NPU Offload Fix + Hardening (2026-03-30)

### Changes

Following interactive serial profiling and comprehensive architecture review
of the NPU hardware offload data path, the following issues were identified
and resolved:

#### Critical: SSH

1. **Dropbear replaced with OpenSSH** -- Dropbear v2025.89 has a fundamental
   incompatibility with OpenSSH 10.0 clients: its `MAX_STRING_LEN=9000`
   buffer overflows during KEXINIT parsing with post-quantum algorithm lists,
   even with `RECV_MAX_PAYLOAD_LEN=262144` and `DROPBEAR_MLKEM768=1` enabled.
   The "String too long" error occurs in `buf_getstring()` at
   `common-algo.c:440` during `read_kex_algos()`. Replaced with
   `openssh-server` + `openssh-sftp-server` + `openssh-client` + `openssh-keygen`.
   All KEX algorithms (mlkem768, sntrup761, curve25519, ECDH, DH) work natively.

#### Critical: NPU Flow Offload

2. **Mark-gated offload temporarily disabled** -- The `10-mark-offload.nft`
   rule (`flow offload @ft` with mark conditions) failed with `No such file
   or directory` because the XDP->skb mark pipeline was not functional:
   bpftool was missing (wrong package name), maps were not pinned, and marks
   never reached `skb->mark`. The standard fw4 `flow add @ft` with
   `flags offload` (enabled via `99-disable-native-hwnat`) handles all
   hardware NPU offload via the kernel flowtable path. Mark-gated QoS
   differentiation will be re-enabled once the full pipeline is verified.

3. **`CONFIG_NET_AIROHA_FLOW_STATS=y` enabled** -- Previously disabled.
   Without flow stats, the sync daemon's debugfs polling returns zero
   counters, making flow lifecycle management impossible. Enables the
   PPE+NPU split counter architecture (4096 stats entries). SRAM capacity
   drops from 8192 to 4096 flow entries (half used for stats), but DRAM
   still provides 16384 entries (20480 total).

4. **bpftool package name fixed** -- `CONFIG_PACKAGE_bpftool=y` was silently
   discarded by `make defconfig` because the package was split into
   `bpftool-minimal` and `bpftool-full` variants. Changed to
   `CONFIG_PACKAGE_bpftool-minimal=y`.

#### High: System Configuration

5. **Sysctl split into two files** -- vm.* settings moved to
   `15-w1700k-vm.conf` (always valid), network settings in
   `20-w1700k-10g-gateway.conf`. Previously, a `write error: Invalid
   argument` on `net.core.netdev_budget_usecs` caused `sysctl -p` to abort
   before reaching the vm.* settings at the end of the single file.
   Removed `netdev_budget_usecs` (not writable on this kernel) and
   `nf_conntrack_buckets` (read-only).

6. **ZRAM set to zstd** via UCI defaults. The kernel default is lzo; the
   zram-swap init script reads from UCI, not from `CONFIG_ZRAM_DEF_COMP`.

7. **uclamp writes guarded** -- Wrapped cgroup v2 uclamp value writes with
   a check for `/sys/devices/system/cpu/cpufreq` existence. The AN7581's
   cpufreq-dt driver fails to register (SMCCC clk issue), so uclamp writes
   fail with "Result not representable".

8. **nginx TLS session tickets disabled** -- Added `ssl_session_tickets off`
   via UCI defaults. Prevents `SSL_do_handshake() failed: binder does not
   verify` errors from stale TLS 1.3 session tickets after firmware upgrades.

#### Medium: Hardware Findings

9. **ARM64 Crypto Extensions confirmed unavailable** -- The AN7581's
   Cortex-A53 is a CE-less variant. CPU features: `fp asimd evtstrm crc32
   cpuid` -- no `aes sha1 sha2 pmull`. CE configs compiled but kernel
   detected no CE hardware. Removed CE-specific configs; kept `CRYPTO_SIMD`
   and `CRYPTO_CRYPTD` (support NEON bit-sliced drivers). NEON `aes-neonbs`
   provides ~2-3x generic C performance.

10. **Dropbear Makefile reverted** -- Removed the `RECV_MAX_PAYLOAD_LEN`
    change since dropbear is no longer used.

### NPU Offload Architecture Confirmation

Serial profiling and upstream code review confirmed:

- **Kernel flowtable path works**: `nft list flowtables` shows `@ft` with
  `flags offload` on wan/lan2/lan3/lan4. The `ndo_setup_tc(TC_SETUP_FT)`
  callback is registered in the airoha_eth driver.
- **PPE/FOE table available**: 32768 entries (16K SRAM + 16K DRAM), 80 bytes
  each. With flow stats enabled: 4096 SRAM + 16384 DRAM = 20480 entries.
- **NPU firmware loaded**: 7/8 RISC-V cores active (core 3 reserved for
  WiFi offload). Firmware manages PPE SRAM via mailbox protocol.
- **WiFi NPU offload patches applied**: 084-085, 111 (mt76 NPU layer).
  Path: Ethernet RX -> PPE hit -> NPU core 3 -> WDMA -> MT7996 TX.
- **L2 bridge offload patches applied**: 068-01/02. Subflow mapping via
  `l2_flows` rhashtable.
- **Standard fw4 flow offload sufficient**: All established TCP/UDP flows
  offloaded to NPU hardware. Mark-gated QoS differentiation is additive.

### Implementation Files (Phase 4)

| File | Change |
|------|--------|
| `seed.config` | -dropbear +openssh, bpftool-minimal |
| `dropbear/Makefile` | Reverted RECV_MAX_PAYLOAD_LEN |
| `an7581/config-6.12` | +FLOW_STATS=y, -ARM64 CE configs |
| `17-w1700k-defaults` | OpenSSH config, ZRAM zstd, nginx ssl_session_tickets |
| `16-w1700k-nft-offload-policy` | Removes mark-gated offload, standard fw4 used |
| `airoha-ebpf.init` | Guard uclamp with cpufreq check |
| `15-w1700k-vm.conf` | New file: vm.* sysctls (always valid) |
| `20-w1700k-10g-gateway.conf` | Network-only sysctls, removed invalid entries |
| `ADR-001-ebpf-soft-hook.md` | This section |

---

## Phase 5: Post-Quantum Compatibility + ZRAM lz4 (2026-03-30)

### Changes

Live testing of Phase 4 revealed that the post-quantum algorithm transition
breaks both SSH and TLS connectivity between modern Linux clients
(Fedora 41+ with OpenSSL 3.5.x / OpenSSH 10.x) and the W1700K.

#### Critical: TLS — ML-KEM768 Hybrid Key Exchange Rejected

OpenSSL 3.5.x clients (curl, Chromium, Floorp on emiemi) send ML-KEM768
hybrid key shares in the TLS 1.3 ClientHello by default (1550 bytes).
The W1700K's OpenSSL 3.5.5 (musl/aarch64 build) either lacks the ML-KEM
provider or has it disabled, causing nginx to send `illegal_parameter`
TLS alert. **All HTTPS connections fail**, including LuCI.

Fixed by adding `ssl_ecdh_curve X25519:secp384r1:secp256r1` to the nginx
`_lan` server block via UCI defaults. This forces classical ECDH curves
and clients negotiate X25519 (128-bit security, standard web baseline).

#### Critical: SSH — PROPOSAL_MAX Overflow (Same Root Cause as Dropbear)

OpenSSH 10.x has a `PROPOSAL_MAX` limit (~8192 bytes per name-list) in
`kex_input_kexinit()`. When both client and server advertise 10+ KEX
algorithms including PQ variants, the combined KEXINIT exceeds this limit.
The OpenSSH 10.2 server rejects with `discard proposal: string is too long`.

This is the **same class of issue** that broke dropbear (where it was
`MAX_STRING_LEN=9000`). Replacing dropbear with OpenSSH did not fix it
because the limit is in the protocol handling, not the SSH implementation.

Fixed by restricting `KexAlgorithms` in `sshd_config` to 3 algorithms:
`curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512`.
The combined KEXINIT stays well under 8192 bytes.

#### High: ZRAM — lz4 Instead of lzo/zstd

The AN7581's Cortex-A53 lacks crypto extensions, making CPU-intensive
compression algorithms disproportionately expensive. lz4 provides:
- 2.8x faster decompression than zstd (1400 vs 500 MB/s)
- 2x faster decompression than lzo (1400 vs 650 MB/s)
- Comparable compression ratio to lzo (2.1:1)
- Sub-microsecond swap page faults (critical for container workloads)

Set via `CONFIG_ZRAM_DEF_COMP_LZ4=y` in kernel config and
`system.zram.comp_algorithm='lz4'` in UCI defaults.

#### High: BPF Map Pinning Fix

The Phase 4 bpftool-based map pinning used `bpftool -j` (JSON mode) with
`jsonfilter` to parse output. This failed silently because bpftool's JSON
format didn't match jsonfilter's expectations. Replaced with plain-text
`bpftool net show` + `grep`/`awk`/`sed` parsing.

#### Low: cgroup subtree_control Errors Suppressed

Writing `"+cpu +cpuset"` in a single `echo` to `cgroup.subtree_control`
produced 3 "Result not representable" errors. Split into two separate
writes (`"+cpu"` then `"+cpuset"`) to avoid the kernel rejecting the
combined operation.

### Implementation Files (Phase 5)

| File | Change |
|------|--------|
| `17-w1700k-defaults` | nginx ssl_ecdh_curve, sshd KexAlgorithms, ZRAM lz4 |
| `an7581/config-6.12` | `CONFIG_ZRAM_DEF_COMP_LZ4=y` |
| `airoha-ebpf.init` | BPF map pinning fix, cgroup split writes |
| `ADR-001-ebpf-soft-hook.md` | This section |

---

## Phase 6: WiFi NZ + DNS Chain + Service Hardening + Network Tuning (2026-03-30)

### Changes

Live device profiling and interactive testing of the Phase 5 build revealed
multiple first-boot usability issues. The device booted stable but required
manual configuration for WiFi, DNS, service management, and password
authentication. Phase 6 establishes a complete out-of-box experience.

#### Critical: DNS Architecture — AdGuard Home + dnsmasq Chain

1. **Pre-seeded AdGuard Home YAML** — AGH was installed but unconfigured,
   requiring manual setup at `:3000` before DNS filtering worked. Pre-seeded
   `adguardhome.yaml` configures:
   - DNS on `:53` (all interfaces) with DoH upstreams (Cloudflare + Google)
   - `.lan` queries forwarded to dnsmasq at `127.0.0.1:54`
   - Private PTR resolution via dnsmasq for DHCP lease hostnames
   - DNSSEC enabled, optimistic caching (4 MB cache)
   - Two pre-configured filter lists (AdGuard DNS filter, AdAway)
   - 5-day query log and statistics retention
   - No default admin password — user completes setup wizard at `:3000`

2. **dnsmasq moved to port 54** — UCI defaults set `port='54'`,
   `noresolv='1'`, `localservice='0'`. dnsmasq handles only `.lan` hostname
   resolution from DHCP leases and `/etc/hosts`. No upstream DNS — AGH
   handles all external resolution.

   ```
   Client → AGH(:53) → DoH (Cloudflare/Google)  [external]
                      → dnsmasq(:54)              [.lan/PTR]
   ```

3. **dnscrypt-proxy and https-dns-proxy disabled** — Redundant with AGH's
   built-in DoH. The https-dns-proxy init script modifies dnsmasq config
   on start (adds `noresolv`, server entries), which conflicts with the
   AGH→dnsmasq chain. Disabled via `19-w1700k-services`.

#### Critical: WiFi NZ Defaults

4. **Three SSIDs configured for NZ regulatory domain** — Tested and verified
   live on device. All radios enabled by default with WPA3:

   | Radio | SSID | Channel | Width | Encryption | ieee80211w |
   |-------|------|---------|-------|------------|------------|
   | 2.4 GHz | `W1700K-2G` | auto | EHT40 | sae-mixed | -- |
   | 5 GHz | `W1700K-5G` | 36 | EHT160 | sae | 2 (required) |
   | 6 GHz | `W1700K-6G` | 37 | EHT320 | sae | 2 (required) |

   - NZ regdomain: 36 dBm 2.4 GHz, 30 dBm 5 GHz UNII-1, 24 dBm 6 GHz
   - EHT160 on 5 GHz: channel 36 spans 5180–5330 MHz (60s DFS CAC at boot)
   - EHT320 on 6 GHz: centre 6105 MHz spans 5945–6265 MHz (ch 1–65)
   - 2.4 GHz EHT40: hostapd falls back to 20 MHz per coexistence rules
   - Default password: `CHANGEME` (forces user to change)

#### Critical: Root Password Fix

5. **SHA-512 password hash** — BusyBox `passwd` generates bcrypt (`$2a$`)
   hashes which musl's `crypt()` doesn't support for OpenSSH authentication.
   Root password set via `openssl passwd -6` to produce SHA-512 (`$6$`) hash
   compatible with both OpenSSH and login. Default: `CHANGEME`. Guarded by
   sentinel file `/etc/ssh/.password_set` to run on first boot only.

#### High: Service Hardening

6. **19 services disabled by default** — Reduces memory footprint (~60 MB),
   CPU overhead, and attack surface. All remain installed and can be
   re-enabled with `/etc/init.d/<service> enable && start`:

   | Category | Disabled Services |
   |----------|-------------------|
   | Routing | frr (zebra/mgmtd/staticd/watchfrr) |
   | IoT | gpsd, mosquitto, ser2net |
   | Auth | radius |
   | Proxy | squid, privoxy, tinyproxy, redsocks |
   | SOCKS5 | microsocks, hev-socks5-server, hev-socks5-tproxy |
   | DNS | dnscrypt-proxy, https-dns-proxy |
   | USB/IP | usbipd |
   | Monitoring | lm-sensors |
   | Ad-blocking | adblock-fast, banip (replaced by AGH) |
   | Relay | socat |

7. **librespeed-go enabled** — Speed test server on `:8989` for WiFi
   performance verification.

#### High: nginx TLS ML-KEM Fix

8. **`ssl_conf_command Groups`** — Phase 5 used `ssl_ecdh_curve` which only
   sets preference but doesn't reject ML-KEM key shares. Upgraded to
   `ssl_conf_command Groups X25519:secp384r1:secp256r1` which explicitly
   limits the TLS 1.3 key exchange to classical ECDH curves. Falls back to
   `ssl_ecdh_curve` if nginx doesn't support `ssl_conf_command`.

#### High: 10G Network Performance Tuning

9. **RPS across all 4 CPUs** — The QDMA has 32 RX/TX queues but only 1
   active IRQ (`airoha_eth.0`). All packets funnelled through CPU0 (98% of
   NET_RX softirqs). Set `rps_cpus=f` on all RX queues for `eth0`, `wan`,
   and `lan2` to distribute packet processing across all 4 A53 cores.

10. **XPS: 8 TX queues per CPU** — Transmit Packet Steering assigns TX
    queues 0–7 to CPU0, 8–15 to CPU1, 16–23 to CPU2, 24–31 to CPU3.
    Ensures cache locality between packet construction and DMA submission.

11. **NAPI busy-poll** — `napi_defer_hard_irqs=2`, `gro_flush_timeout=20000`
    (20 µs). Defers 2 interrupts and batches GRO aggregation, reducing
    interrupt overhead on 10G interfaces. Significant for the single-IRQ
    QDMA architecture.

12. **RFS flow table** — `rps_sock_flow_entries=32768` globally,
    `rps_flow_cnt=1024` per queue. Ensures flows are consistently processed
    on the same CPU that the receiving socket is scheduled on, reducing
    cross-core cache bouncing.

### Implementation Files (Phase 6)

| File | Change |
|------|--------|
| `adguardhome.yaml` | Pre-seeded AGH config (new) |
| `17-w1700k-defaults` | SHA-512 root pw, dnsmasq :54, nginx ssl_conf_command |
| `18-w1700k-wifi` | NZ WiFi defaults, 3 SSIDs (new) |
| `19-w1700k-services` | Disable 19 services, enable librespeed-go (new) |
| `airoha-ebpf.init` | RPS/XPS/NAPI tuning for 10G |
| `20-w1700k-10g-gateway.conf` | rps_sock_flow_entries sysctl |
| `ADR-001-ebpf-soft-hook.md` | This section |
