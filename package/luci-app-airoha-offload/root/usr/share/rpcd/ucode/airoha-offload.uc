// SPDX-License-Identifier: GPL-2.0-or-later
// rpcd ucode plugin for Airoha eBPF/XDP offload telemetry

'use strict';

import { popen, readfile } from 'fs';

function exec_cmd(command) {
	let p = popen(command, 'r');
	if (p == null) return { code: -1, out: '' };
	let out = '';
	for (let line = p.read('line'); length(line); line = p.read('line'))
		out += line;
	let code = p.close();
	return { code, out: rtrim(out) };
}

const methods = {
	get_status: {
		call: function() {
			let daemon_r = exec_cmd('pgrep -c airoha-sync-daemon');
			let daemon_count = int(trim(daemon_r.out)) || 0;

			let stats_r = exec_cmd('sysctl -n kernel.bpf_stats_enabled');
			let bpf_stats = int(trim(stats_r.out)) || 0;

			// Check dynamic debug for airoha_eth
			let dbg_r = exec_cmd("grep -c 'airoha_eth.*=p' /sys/kernel/debug/dynamic_debug/control 2>/dev/null || echo 0");
			let soft_hook_debug = int(trim(dbg_r.out)) > 0 ? 1 : 0;

			return {
				daemon_running: daemon_count > 0 ? 1 : 0,
				daemon_count,
				bpf_stats_enabled: bpf_stats,
				soft_hook_debug
			};
		}
	},

	get_programs: {
		call: function() {
			let r = exec_cmd('/usr/sbin/bpftool prog show --json');
			if (r.code != 0 || length(r.out) == 0) return { programs: [] };
			try {
				let progs = json(r.out);
				let result = [];
				for (let p in progs) {
					push(result, {
						id: p.id,
						type: p.type,
						name: p.name || '',
						tag: p.tag || '',
						run_cnt: p.run_cnt || 0,
						run_time_ns: p.run_time_ns || 0,
						map_ids: p.map_ids || []
					});
				}
				return { programs: result };
			} catch(e) {
				return { programs: [], error: 'parse error' };
			}
		}
	},

	get_maps: {
		call: function() {
			let r = exec_cmd('/usr/sbin/bpftool map show --json');
			if (r.code != 0 || length(r.out) == 0) return { maps: [] };
			try {
				let maps = json(r.out);
				let result = [];
				for (let m in maps) {
					push(result, {
						id: m.id,
						type: m.type,
						name: m.name || '',
						key_size: m.key_size || 0,
						value_size: m.value_size || 0,
						max_entries: m.max_entries || 0,
						bytes_memlock: m.bytes_memlock || 0
					});
				}
				return { maps: result };
			} catch(e) {
				return { maps: [], error: 'parse error' };
			}
		}
	},

	get_ppe_flows: {
		call: function() {
			let content = readfile('/sys/kernel/debug/ppe/bind');
			if (!content || length(content) == 0) return { flows: [] };

			let flows = [];
			let lines = split(rtrim(content), '\n');
			for (let line in lines) {
				line = trim(line);
				if (length(line) == 0) continue;

				// Parse: HASH STATE TYPE orig=... new=... eth=... etype=... ...
				let m = match(line, /^([0-9a-f]{5})\s+(\S+)\s+(.+?)\s+orig=(\S+)\s+new=(\S+)\s+eth=(\S+)\s+etype=(\S+)/);
				if (!m) continue;

				let hash = m[1];
				let state = m[2];
				let type_str = trim(m[3]);
				let orig = m[4];
				let new_addr = m[5];
				let eth = m[6];
				let etype = m[7];

				// Parse eth: SRCMAC->DSTMAC
				let eth_parts = split(eth, '->');
				let eth_src = eth_parts[0] || '';
				let eth_dst = eth_parts[1] || '';

				// Parse vlan from remainder
				let vlan_m = match(line, /vlan=(\S+)/);
				let vlan = vlan_m ? vlan_m[1] : '0,0';

				push(flows, {
					hash,
					state,
					type: type_str,
					orig,
					'new': new_addr,
					eth_src,
					eth_dst,
					etype,
					vlan
				});
			}
			return { flows };
		}
	},

	get_interfaces: {
		call: function() {
			let r = exec_cmd('/usr/sbin/bpftool net show --json');
			if (r.code != 0 || length(r.out) == 0) return { interfaces: [] };
			try {
				let nets = json(r.out);
				let result = [];
				for (let iface_entry in nets) {
					let xdp_id = null;
					let xdp_mode = null;
					let tc_ingress_id = null;

					for (let x in (iface_entry.xdp || [])) {
						xdp_id = x.id;
						xdp_mode = x.mode || 'unknown';
					}
					for (let t in (iface_entry.tc || [])) {
						if (t.kind == 'bpf') {
							tc_ingress_id = t.id;
							break;
						}
					}
					push(result, {
						iface: iface_entry.devname || '',
						xdp_id,
						xdp_mode,
						tc_ingress_id
					});
				}
				return { interfaces: result };
			} catch(e) {
				return { interfaces: [], error: 'parse error' };
			}
		}
	},

	restart_daemon: {
		call: function() {
			let r = exec_cmd('/etc/init.d/airoha-ebpf restart');
			return { success: r.code == 0, code: r.code };
		}
	},

	flush_flowtable: {
		call: function() {
			let r = exec_cmd('nft flush flowtable inet fw4 ft');
			return { success: r.code == 0, code: r.code };
		}
	},

	toggle_bpf_stats: {
		args: { enable: 0 },
		call: function(request) {
			let enable = request.args?.enable ? 1 : 0;
			let r = exec_cmd('sysctl -w kernel.bpf_stats_enabled=' + enable);
			return { success: r.code == 0, enabled: enable };
		}
	},

	toggle_soft_hook_debug: {
		args: { enable: 0 },
		call: function(request) {
			let flag = request.args?.enable ? '+p' : '-p';
			// Write to dynamic_debug/control — shell redirection requires sh -c
			let r = exec_cmd("sh -c \"echo 'module airoha_eth " + flag + "' > /sys/kernel/debug/dynamic_debug/control\"");
			return { success: r.code == 0, enabled: request.args?.enable ? 1 : 0 };
		}
	}
};

return { 'luci.airoha_offload': methods };
