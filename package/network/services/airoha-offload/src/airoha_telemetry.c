// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright: Joel Wirāmu Pauling <aenertia@aenertia.net>
//
// Artifact Name: airoha_telemetry.c
// Purpose: Placeholder for kprobe-based NPU telemetry.
//
// DESIGN NOTE:
// This file is reserved for a future kprobe program that attaches to
// airoha_ppe_foe_entry_get_stats() (airoha_ppe.c) to stream real-time
// hardware flow statistics to userspace via ring buffer.
//
// The target function signature is:
//
//   static void airoha_ppe_foe_entry_get_stats(struct airoha_ppe *ppe,
//                                               struct airoha_npu *npu,
//                                               struct airoha_foe_entry *hwe,
//                                               u16 hash)
//
// For now, the sync daemon polls debugfs instead:
//   /sys/kernel/debug/ppe0/bind
//   /sys/kernel/debug/ppe1/bind
//
// This avoids the need for:
//   - CO-RE / vmlinux.h (complex to generate in OpenWrt build)
//   - Kernel patch 998 (custom telemetry hook export)
//   - bpf_probe_read_kernel() of fragile FOE entry internals
//
// When BTF/CO-RE support is fully validated on the AN7581 platform,
// this file should be replaced with a real kprobe program that:
//   1. Attaches to airoha_ppe_foe_entry_get_stats via SEC("kprobe/...")
//   2. Reads the FOE hash index (4th argument, u16)
//   3. Submits (hash, timestamp) tuples to a ring buffer
//   4. Lets the daemon correlate hash -> flow -> stats
//
// See: ADR-001-ebpf-soft-hook.md

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";
