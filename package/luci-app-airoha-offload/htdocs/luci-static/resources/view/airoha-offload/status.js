'use strict';
'require view';
'require rpc';
'require poll';
'require dom';
'require ui';

var callGetStatus = rpc.declare({
	object: 'luci.airoha_offload',
	method: 'get_status'
});

var callGetPrograms = rpc.declare({
	object: 'luci.airoha_offload',
	method: 'get_programs'
});

var callGetMaps = rpc.declare({
	object: 'luci.airoha_offload',
	method: 'get_maps'
});

var callGetPpeFlows = rpc.declare({
	object: 'luci.airoha_offload',
	method: 'get_ppe_flows'
});

var callGetInterfaces = rpc.declare({
	object: 'luci.airoha_offload',
	method: 'get_interfaces'
});

var callRestartDaemon = rpc.declare({
	object: 'luci.airoha_offload',
	method: 'restart_daemon'
});

var callFlushFlowtable = rpc.declare({
	object: 'luci.airoha_offload',
	method: 'flush_flowtable'
});

var callToggleBpfStats = rpc.declare({
	object: 'luci.airoha_offload',
	method: 'toggle_bpf_stats',
	params: ['enable']
});

var callToggleSoftHookDebug = rpc.declare({
	object: 'luci.airoha_offload',
	method: 'toggle_soft_hook_debug',
	params: ['enable']
});

return view.extend({
	load: function() {
		return Promise.all([
			callGetStatus(),
			callGetPrograms(),
			callGetMaps(),
			callGetPpeFlows(),
			callGetInterfaces()
		]);
	},

	renderStatus: function(status) {
		var daemonBadge = status.daemon_running
			? E('span', { 'class': 'label active' }, _('Running'))
			: E('span', { 'class': 'label danger' }, _('Stopped'));

		var statsBanner = !status.bpf_stats_enabled
			? E('div', { 'class': 'cbi-section warning' },
				_('BPF stats disabled — run counts will be zero. Enable via Toggle BPF Stats button.'))
			: E('div', {});

		return E('div', { 'class': 'cbi-section', 'id': 'ebpf-status' }, [
			E('h3', {}, _('Daemon Status')),
			E('div', { 'class': 'cbi-section-node' }, [
				E('div', {}, [E('label', {}, _('Sync Daemon: ')), daemonBadge]),
				E('div', {}, [
					E('label', {}, _('Soft Hook Debug: ')),
					E('span', {}, status.soft_hook_debug ? _('Enabled') : _('Disabled'))
				]),
				statsBanner
			])
		]);
	},

	renderInterfaces: function(interfaces) {
		var rows = interfaces.length ? interfaces.map(function(i) {
			return E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td' }, i.iface || '-'),
				E('td', { 'class': 'td' }, i.xdp_mode || '-'),
				E('td', { 'class': 'td' }, i.xdp_id != null ? String(i.xdp_id) : '-'),
				E('td', { 'class': 'td' }, i.tc_ingress_id != null ? String(i.tc_ingress_id) : '-')
			]);
		}) : [E('tr', { 'class': 'tr' }, [E('td', { 'class': 'td', 'colspan': '4' }, _('No XDP/TC-BPF attachments found'))])];

		return E('div', { 'class': 'cbi-section', 'id': 'ebpf-interfaces' }, [
			E('h3', {}, _('Interface Attachment')),
			E('div', { 'class': 'cbi-section-node' }, [
				E('table', { 'class': 'table' }, [
					E('tr', { 'class': 'tr table-titles' }, [
						E('th', { 'class': 'th' }, _('Interface')),
						E('th', { 'class': 'th' }, _('XDP Mode')),
						E('th', { 'class': 'th' }, _('XDP Prog ID')),
						E('th', { 'class': 'th' }, _('TC-BPF Prog ID'))
					])
				].concat(rows))
			])
		]);
	},

	renderPrograms: function(programs) {
		var rows = programs.length ? programs.map(function(p) {
			var runtime_us = p.run_time_ns ? Math.round(p.run_time_ns / 1000) : 0;
			return E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td' }, String(p.id || '-')),
				E('td', { 'class': 'td' }, p.name || '-'),
				E('td', { 'class': 'td' }, p.type || '-'),
				E('td', { 'class': 'td' }, p.tag || '-'),
				E('td', { 'class': 'td' }, String(p.run_cnt || 0)),
				E('td', { 'class': 'td' }, String(runtime_us))
			]);
		}) : [E('tr', { 'class': 'tr' }, [E('td', { 'class': 'td', 'colspan': '6' }, _('No BPF programs loaded'))])];

		return E('div', { 'class': 'cbi-section', 'id': 'ebpf-programs' }, [
			E('h3', {}, _('BPF Programs')),
			E('div', { 'class': 'cbi-section-node' }, [
				E('table', { 'class': 'table' }, [
					E('tr', { 'class': 'tr table-titles' }, [
						E('th', { 'class': 'th' }, _('ID')),
						E('th', { 'class': 'th' }, _('Name')),
						E('th', { 'class': 'th' }, _('Type')),
						E('th', { 'class': 'th' }, _('Tag')),
						E('th', { 'class': 'th' }, _('Run Count')),
						E('th', { 'class': 'th' }, _('Runtime (µs)'))
					])
				].concat(rows))
			])
		]);
	},

	renderMaps: function(maps) {
		var rows = maps.length ? maps.map(function(m) {
			var mem_kb = m.bytes_memlock ? Math.round(m.bytes_memlock / 1024) : 0;
			return E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td' }, String(m.id || '-')),
				E('td', { 'class': 'td' }, m.name || '-'),
				E('td', { 'class': 'td' }, m.type || '-'),
				E('td', { 'class': 'td' }, String(m.key_size || 0)),
				E('td', { 'class': 'td' }, String(m.value_size || 0)),
				E('td', { 'class': 'td' }, String(m.max_entries || 0)),
				E('td', { 'class': 'td' }, String(mem_kb))
			]);
		}) : [E('tr', { 'class': 'tr' }, [E('td', { 'class': 'td', 'colspan': '7' }, _('No BPF maps found'))])];

		return E('div', { 'class': 'cbi-section', 'id': 'ebpf-maps' }, [
			E('h3', {}, _('BPF Maps')),
			E('div', { 'class': 'cbi-section-node' }, [
				E('table', { 'class': 'table' }, [
					E('tr', { 'class': 'tr table-titles' }, [
						E('th', { 'class': 'th' }, _('ID')),
						E('th', { 'class': 'th' }, _('Name')),
						E('th', { 'class': 'th' }, _('Type')),
						E('th', { 'class': 'th' }, _('Key Sz')),
						E('th', { 'class': 'th' }, _('Val Sz')),
						E('th', { 'class': 'th' }, _('Max Entries')),
						E('th', { 'class': 'th' }, _('Mem (KB)'))
					])
				].concat(rows))
			])
		]);
	},

	renderPpeFlows: function(flows) {
		function stateLabel(state) {
			var cls = 'label';
			if (state === 'BND') cls += ' active';
			else if (state === 'UNB') cls += ' notice';
			return E('span', { 'class': cls }, state);
		}

		var rows = flows.length ? flows.map(function(f) {
			return E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td' }, f.hash || '-'),
				E('td', { 'class': 'td' }, stateLabel(f.state || '-')),
				E('td', { 'class': 'td' }, f.type || '-'),
				E('td', { 'class': 'td' }, f.orig || '-'),
				E('td', { 'class': 'td' }, f['new'] || '-'),
				E('td', { 'class': 'td' }, (f.eth_src || '-') + ' \u2192 ' + (f.eth_dst || '-')),
				E('td', { 'class': 'td' }, f.vlan || '-')
			]);
		}) : [E('tr', { 'class': 'tr' }, [E('td', { 'class': 'td', 'colspan': '7' }, _('No active PPE flows'))])];

		return E('div', { 'class': 'cbi-section', 'id': 'ebpf-flows' }, [
			E('h3', {}, _('PPE Flow Table')),
			E('div', { 'class': 'cbi-section-node' }, [
				E('table', { 'class': 'table' }, [
					E('tr', { 'class': 'tr table-titles' }, [
						E('th', { 'class': 'th' }, _('Hash')),
						E('th', { 'class': 'th' }, _('State')),
						E('th', { 'class': 'th' }, _('Type')),
						E('th', { 'class': 'th' }, _('Original')),
						E('th', { 'class': 'th' }, _('Translated')),
						E('th', { 'class': 'th' }, _('Src MAC \u2192 Dst MAC')),
						E('th', { 'class': 'th' }, _('VLAN'))
					])
				].concat(rows))
			])
		]);
	},

	renderControls: function(status) {
		function makeButton(id, label, confirmText, action) {
			var btn = E('button', {
				'class': 'cbi-button cbi-button-apply',
				'id': id,
				'click': function() {
					ui.showModal(_('Confirm'), [
						E('p', {}, confirmText),
						E('div', { 'class': 'right' }, [
							E('button', {
								'class': 'cbi-button',
								'click': function() { ui.hideModal(); }
							}, _('Cancel')),
							E('button', {
								'class': 'cbi-button cbi-button-apply',
								'click': function() {
									ui.hideModal();
									btn.disabled = true;
									return action().then(function(result) {
										btn.disabled = false;
										if (result && result.success) {
											ui.addNotification(null, E('p', {}, _('Action completed successfully.')), 'info');
										} else {
											ui.addNotification(null, E('p', {}, _('Action failed.')), 'danger');
										}
									}).catch(function(err) {
										btn.disabled = false;
										ui.addNotification(null, E('p', {}, _('Error: ') + String(err)), 'danger');
									});
								}
							}, _('Confirm'))
						])
					]);
				}
			}, label);
			return btn;
		}

		var statsLabel = status.bpf_stats_enabled ? _('Disable BPF Stats') : _('Enable BPF Stats');
		var statsAction = status.bpf_stats_enabled
			? function() { return callToggleBpfStats(0); }
			: function() { return callToggleBpfStats(1); };

		var debugLabel = status.soft_hook_debug ? _('Disable Soft Hook Debug') : _('Enable Soft Hook Debug');
		var debugAction = status.soft_hook_debug
			? function() { return callToggleSoftHookDebug(0); }
			: function() { return callToggleSoftHookDebug(1); };

		return E('div', { 'class': 'cbi-section', 'id': 'ebpf-controls' }, [
			E('h3', {}, _('Controls')),
			E('div', { 'class': 'cbi-section-node' }, [
				makeButton('btn-restart', _('Restart Daemon'),
					_('This will restart the airoha-ebpf service. Active flows will briefly drop.'),
					callRestartDaemon),
				' ',
				makeButton('btn-flush', _('Flush Flowtable'),
					_('This will flush the nftables flowtable. Offloaded flows will fall back to software.'),
					callFlushFlowtable),
				' ',
				makeButton('btn-bpfstats', statsLabel,
					_('Toggle kernel BPF statistics collection.'),
					statsAction),
				' ',
				makeButton('btn-softdebug', debugLabel,
					_('Toggle dynamic debug output for airoha_eth kernel module.'),
					debugAction)
			])
		]);
	},

	render: function(data) {
		var status = data[0] || {};
		var programs = (data[1] || {}).programs || [];
		var maps = (data[2] || {}).maps || [];
		var flows = (data[3] || {}).flows || [];
		var interfaces = (data[4] || {}).interfaces || [];

		var v = this;

		var container = E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, _('Airoha eBPF Offload')),
			v.renderStatus(status),
			v.renderInterfaces(interfaces),
			v.renderPrograms(programs),
			v.renderMaps(maps),
			v.renderPpeFlows(flows),
			v.renderControls(status)
		]);

		poll.add(function() {
			return Promise.all([
				callGetStatus(),
				callGetPrograms(),
				callGetMaps(),
				callGetPpeFlows(),
				callGetInterfaces()
			]).then(function(refreshed) {
				var s = refreshed[0] || {};
				var p = (refreshed[1] || {}).programs || [];
				var m = (refreshed[2] || {}).maps || [];
				var f = (refreshed[3] || {}).flows || [];
				var i = (refreshed[4] || {}).interfaces || [];

				dom.content(container.querySelector('#ebpf-status'), v.renderStatus(s).childNodes);
				dom.content(container.querySelector('#ebpf-interfaces'), v.renderInterfaces(i).childNodes);
				dom.content(container.querySelector('#ebpf-programs'), v.renderPrograms(p).childNodes);
				dom.content(container.querySelector('#ebpf-maps'), v.renderMaps(m).childNodes);
				dom.content(container.querySelector('#ebpf-flows'), v.renderPpeFlows(f).childNodes);
				dom.content(container.querySelector('#ebpf-controls'), v.renderControls(s).childNodes);
			});
		}, 5);

		return container;
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
