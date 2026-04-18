# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright: Joel Wirāmu Pauling <aenertia@aenertia.net>
#
# Artifact Name: Makefile
# Purpose: OpenWrt package definition for the eBPF Soft Hook architecture.
#          Compiles the XDP datapath (via bpf-headers/CompileBPF) and the
#          userspace sync daemon.  Follows the qosify Makefile pattern.

include $(TOPDIR)/rules.mk

PKG_NAME:=airoha-offload
PKG_RELEASE:=5

PKG_LICENSE:=GPL-2.0-or-later
PKG_MAINTAINER:=Joel Wirāmu Pauling <aenertia@aenertia.net>

PKG_BUILD_DEPENDS:=bpf-headers
PKG_FLAGS:=nonshared

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/bpf.mk

define Package/airoha-offload
  SECTION:=net
  CATEGORY:=Network
  TITLE:=eBPF/XDP Soft Hook & Sync Daemon for Airoha AN7581
  DEPENDS:=@TARGET_airoha +libbpf +libnetfilter-conntrack +libmnl +ip-full +libpthread +bpftool-minimal $(BPF_DEPENDS)
endef

define Package/airoha-offload/description
  eBPF-based ingress flow classifier and hardware stats synchronisation
  daemon for Airoha AN7581 (W1700K).  The XDP program classifies packets
  and submits flow keys to a ring buffer.  The daemon polls PPE debugfs
  for hardware flow counters and syncs deltas back to conntrack.
  Coexists with kernel nft_flow_offload HWNAT — does not replace it.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	# Compile eBPF XDP datapath via OpenWrt bpf-headers toolchain
	$(call CompileBPF,$(PKG_BUILD_DIR)/airoha_hybrid_offload.c)
	# Compile TC-BPF classifier for MTK DSA user ports (lan3/lan4)
	$(call CompileBPF,$(PKG_BUILD_DIR)/airoha_dsa_classify.c)
	# Compile userspace sync daemon
	$(TARGET_CC) $(TARGET_CFLAGS) -Wall \
		-o $(PKG_BUILD_DIR)/airoha-sync-daemon \
		$(PKG_BUILD_DIR)/airoha-sync-daemon.c \
		$(TARGET_LDFLAGS) -lbpf -lnetfilter_conntrack -lmnl -lpthread
endef

define Package/airoha-offload/install
	$(INSTALL_DIR) $(1)/lib/bpf
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/airoha_hybrid_offload.o $(1)/lib/bpf/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/airoha_dsa_classify.o $(1)/lib/bpf/

	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/airoha-sync-daemon $(1)/usr/sbin/

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/airoha-ebpf.init $(1)/etc/init.d/airoha-ebpf

	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/99-disable-native-hwnat \
		$(1)/etc/uci-defaults/99-disable-native-hwnat

	$(INSTALL_DIR) $(1)/usr/share/nftables.d/ruleset-post
	$(INSTALL_DATA) ./files/10-offload-veto.nft $(1)/usr/share/nftables.d/ruleset-post/
endef

$(eval $(call BuildPackage,airoha-offload))
