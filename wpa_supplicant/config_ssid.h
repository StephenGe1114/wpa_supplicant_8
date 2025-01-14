/*
 * WPA Supplicant / Network configuration structures
 * Copyright (c) 2003-2008, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef CONFIG_SSID_H
#define CONFIG_SSID_H

#include "common/defs.h"
#include "eap_peer/eap_config.h"

#define MAX_SSID_LEN 32


#define DEFAULT_EAP_WORKAROUND ((unsigned int) -1)
#define DEFAULT_EAPOL_FLAGS (EAPOL_FLAG_REQUIRE_KEY_UNICAST | \
			     EAPOL_FLAG_REQUIRE_KEY_BROADCAST)
#define DEFAULT_PROTO (WPA_PROTO_WPA | WPA_PROTO_RSN)
#define DEFAULT_KEY_MGMT (WPA_KEY_MGMT_PSK | WPA_KEY_MGMT_IEEE8021X)
#define DEFAULT_PAIRWISE (WPA_CIPHER_CCMP | WPA_CIPHER_TKIP)
#define DEFAULT_GROUP (WPA_CIPHER_CCMP | WPA_CIPHER_TKIP | \
		       WPA_CIPHER_WEP104 | WPA_CIPHER_WEP40)
#define DEFAULT_FRAGMENT_SIZE 1398

#define DEFAULT_BG_SCAN_PERIOD -1
#define DEFAULT_DISABLE_HT 0
#define DEFAULT_DISABLE_HT40 0
#define DEFAULT_DISABLE_MAX_AMSDU -1 /* no change */
#define DEFAULT_AMPDU_FACTOR -1 /* no change */
#define DEFAULT_AMPDU_DENSITY -1 /* no change */

/**
 * struct wpa_ssid - Network configuration data
 *
 * This structure includes all the configuration variables for a network. This
 * data is included in the per-interface configuration data as an element of
 * the network list, struct wpa_config::ssid. Each network block in the
 * configuration is mapped to a struct wpa_ssid instance.
 */
// 用于存储某个无线网络的配置信息（如所支持的安全类型、优先级等）。它其实是图4-6所示wpa_supplicant.conf中无线网络配置项在代码中的反映（conf文件中每一个network项都对应一个wpa_ssid对象）
struct wpa_ssid {
	/**
	 * next - Next network in global list
	 *
	 * This pointer can be used to iterate over all networks. The head of
	 * this list is stored in the ssid field of struct wpa_config.
	 */
	struct wpa_ssid *next; // 所有wpa_ssid对象都保存在一个链表中，头指针保存于另外一个结构体wpa_config的ssid变量中

	/**
	 * pnext - Next network in per-priority list
	 *
	 * This pointer can be used to iterate over all networks in the same
	 * priority class. The heads of these list are stored in the pssid
	 * fields of struct wpa_config.
	 */
	struct wpa_ssid *pnext; // wpa_ssid还可以按priority保存在另一个链表中，头指针为wpa_config的pssid变量

	/**
	 * id - Unique id for the network
	 *
	 * This identifier is used as a unique identifier for each network
	 * block when using the control interface. Each network is allocated an
	 * id when it is being created, either when reading the configuration
	 * file or when a new network is added through the control interface.
	 */
	int id; // 每一个无线网络都有一个唯一的编号。参考4.2.3.1节"命令介绍"中的ADD_NETWORK命令

	/**
	 * priority - Priority group
	 *
	 * By default, all networks will get same priority group (0). If some
	 * of the networks are more desirable, this field can be used to change
	 * the order in which wpa_supplicant goes through the networks when
	 * selecting a BSS. The priority groups will be iterated in decreasing
	 * priority (i.e., the larger the priority value, the sooner the
	 * network is matched against the scan results). Within each priority
	 * group, networks will be selected based on security policy, signal
	 * strength, etc.
	 *
	 * Please note that AP scanning with scan_ssid=1 and ap_scan=2 mode are
	 * not using this priority to select the order for scanning. Instead,
	 * they try the networks in the order that used in the configuration
	 * file.
	 */
	int priority; // 该无线网络对应的priority值,默认为0

	/**
	 * ssid - Service set identifier (network name)
	 *
	 * This is the SSID for the network. For wireless interfaces, this is
	 * used to select which network will be used. If set to %NULL (or
	 * ssid_len=0), any SSID can be used. For wired interfaces, this must
	 * be set to %NULL. Note: SSID may contain any characters, even nul
	 * (ASCII 0) and as such, this should not be assumed to be a nul
	 * terminated string. ssid_len defines how many characters are valid
	 * and the ssid field is not guaranteed to be nul terminated.
	 */
	u8 *ssid; // 次无线网络的ssid(即无线网络名)

	/**
	 * ssid_len - Length of the SSID
	 */
	size_t ssid_len; // ssid变量的长度

	/**
	 * bssid - BSSID
	 *
	 * If set, this network block is used only when associating with the AP
	 * using the configured BSSID
	 *
	 * If this is a persistent P2P group (disabled == 2), this is the GO
	 * Device Address.
	 */
	u8 bssid[ETH_ALEN]; // 用于保存bssid,数组长度为ETH_ALEN

	/**
	 * bssid_set - Whether BSSID is configured for this network
	 */
	int bssid_set; // 该无线网络是否设置了bssid变量

	/**
	 * psk - WPA pre-shared key (256 bits)
	 */
	u8 psk[32]; // 用于保存wpa中的pre-shared key

	/**
	 * psk_set - Whether PSK field is configured
	 */
	int psk_set; // 是否设置了上述的psk参数

	/**
	 * passphrase - WPA ASCII passphrase
	 *
	 * If this is set, psk will be generated using the SSID and passphrase
	 * configured for the network. ASCII passphrase must be between 8 and
	 * 63 characters (inclusive).
	 */
	// 该变量只和WPA/WPA2-PSK模式有关，用于存储我们输入的字符串密码。而实际上，规范要求使用的却是图4-10中的psk变量。结合3.3.7节中关于key和password的介绍可知，用户一般只设置字符串形式的password。而WPAS将根据它和ssid进行一定的计算以得到最终使用的PSK。参考资料[3]中有PSK计算方法。
	char *passphrase; // 为wpa设置的ASII字符密码

	/**
	 * ext_psk - PSK/passphrase name in external storage
	 *
	 * If this is set, PSK/passphrase will be fetched from external storage
	 * when requesting association with the network.
	 */
	char *ext_psk; // 

	/**
	 * pairwise_cipher - Bitfield of allowed pairwise ciphers, WPA_CIPHER_*
	 */
	int pairwise_cipher; // 用于单播数据加密的密钥对类型

	/**
	 * group_cipher - Bitfield of allowed group ciphers, WPA_CIPHER_*
	 */
	int group_cipher; // 用于组播数据加密的密钥对类型

	/**
	 * key_mgmt - Bitfield of allowed key management protocols
	 *
	 * WPA_KEY_MGMT_*
	 */
	int key_mgmt; // 密钥管理类型

	/**
	 * bg_scan_period - Background scan period in seconds, 0 to disable, or
	 * -1 to indicate no change to default driver configuration
	 */
	int bg_scan_period;

	/**
	 * proto - Bitfield of allowed protocols, WPA_PROTO_*
	 */
	int proto; // 该无线网络支持的安全保护类型

	/**
	 * auth_alg -  Bitfield of allowed authentication algorithms
	 *
	 * WPA_AUTH_ALG_*
	 */
	int auth_alg; // 该无线网络支持的身份验证类型

	/**
	 * scan_ssid - Scan this SSID with Probe Requests
	 *
	 * scan_ssid can be used to scan for APs using hidden SSIDs.
	 * Note: Many drivers do not support this. ap_mode=2 can be used with
	 * such drivers to use hidden SSIDs.
	 */
	int scan_ssid; // 是否利用probe request帧扫描此ssid对应的无线网络

#ifdef IEEE8021X_EAPOL
#define EAPOL_FLAG_REQUIRE_KEY_UNICAST BIT(0)
#define EAPOL_FLAG_REQUIRE_KEY_BROADCAST BIT(1)
	/**
	 * eapol_flags - Bit field of IEEE 802.1X/EAPOL options (EAPOL_FLAG_*)
	 */
	int eapol_flags; // EAPOL选项

	/**
	 * eap - EAP peer configuration for this network
	 */
	struct eap_peer_config eap; // eap_peer端设置信息
#endif /* IEEE8021X_EAPOL */

#define NUM_WEP_KEYS 4
#define MAX_WEP_KEY_LEN 16
	/**
	 * wep_key - WEP keys
	 */
	u8 wep_key[NUM_WEP_KEYS][MAX_WEP_KEY_LEN];

	/**
	 * wep_key_len - WEP key lengths
	 */
	size_t wep_key_len[NUM_WEP_KEYS];

	/**
	 * wep_tx_keyidx - Default key index for TX frames using WEP
	 */
	int wep_tx_keyidx;

	/**
	 * proactive_key_caching - Enable proactive key caching
	 *
	 * This field can be used to enable proactive key caching which is also
	 * known as opportunistic PMKSA caching for WPA2. This is disabled (0)
	 * by default. Enable by setting this to 1.
	 *
	 * Proactive key caching is used to make supplicant assume that the APs
	 * are using the same PMK and generate PMKSA cache entries without
	 * doing RSN pre-authentication. This requires support from the AP side
	 * and is normally used with wireless switches that co-locate the
	 * authenticator.
	 */
	int proactive_key_caching;

	/**
	 * mixed_cell - Whether mixed cells are allowed
	 *
	 * This option can be used to configure whether so called mixed cells,
	 * i.e., networks that use both plaintext and encryption in the same
	 * SSID, are allowed. This is disabled (0) by default. Enable by
	 * setting this to 1.
	 */
	int mixed_cell;

#ifdef IEEE8021X_EAPOL

	/**
	 * leap - Number of EAP methods using LEAP
	 *
	 * This field should be set to 1 if LEAP is enabled. This is used to
	 * select IEEE 802.11 authentication algorithm.
	 */
	int leap;

	/**
	 * non_leap - Number of EAP methods not using LEAP
	 *
	 * This field should be set to >0 if any EAP method other than LEAP is
	 * enabled. This is used to select IEEE 802.11 authentication
	 * algorithm.
	 */
	int non_leap;

	/**
	 * eap_workaround - EAP workarounds enabled
	 *
	 * wpa_supplicant supports number of "EAP workarounds" to work around
	 * interoperability issues with incorrectly behaving authentication
	 * servers. This is recommended to be enabled by default because some
	 * of the issues are present in large number of authentication servers.
	 *
	 * Strict EAP conformance mode can be configured by disabling
	 * workarounds with eap_workaround = 0.
	 */
	unsigned int eap_workaround;

#endif /* IEEE8021X_EAPOL */

	/**
	 * mode - IEEE 802.11 operation mode (Infrastucture/IBSS)
	 *
	 * 0 = infrastructure (Managed) mode, i.e., associate with an AP.
	 *
	 * 1 = IBSS (ad-hoc, peer-to-peer)
	 *
	 * 2 = AP (access point)
	 *
	 * 3 = P2P Group Owner (can be set in the configuration file)
	 *
	 * 4 = P2P Group Formation (used internally; not in configuration
	 * files)
	 *
	 * Note: IBSS can only be used with key_mgmt NONE (plaintext and
	 * static WEP) and key_mgmt=WPA-NONE (fixed group key TKIP/CCMP). In
	 * addition, ap_scan has to be set to 2 for IBSS. WPA-None requires
	 * following network block options: proto=WPA, key_mgmt=WPA-NONE,
	 * pairwise=NONE, group=TKIP (or CCMP, but not both), and psk must also
	 * be set (either directly or using ASCII passphrase).
	 */
	// 基础结构型网络中，如果STA和某个AP成功连接的话，STA也称为Managed STA（对应枚举值为WPAS_MODE_INFRA）
	enum wpas_mode {
		WPAS_MODE_INFRA = 0, // 代表基础结构型网络中的STA
		WPAS_MODE_IBSS = 1, // 代表IBSS网络的模式
		WPAS_MODE_AP = 2, // 代表基础结构型网络中的AP
		WPAS_MODE_P2P_GO = 3, // P2P相关
		WPAS_MODE_P2P_GROUP_FORMATION = 4,
	} mode;

	/**
	 * disabled - Whether this network is currently disabled
	 *
	 * 0 = this network can be used (default).
	 * 1 = this network block is disabled (can be enabled through
	 * ctrl_iface, e.g., with wpa_cli or wpa_gui).
	 * 2 = this network block includes parameters for a persistent P2P
	 * group (can be used with P2P ctrl_iface commands)
	 */
	int disabled;

	/**
	 * peerkey -  Whether PeerKey handshake for direct links is allowed
	 *
	 * This is only used when both RSN/WPA2 and IEEE 802.11e (QoS) are
	 * enabled.
	 *
	 * 0 = disabled (default)
	 * 1 = enabled
	 */
	int peerkey;

	/**
	 * id_str - Network identifier string for external scripts
	 *
	 * This value is passed to external ctrl_iface monitors in
	 * WPA_EVENT_CONNECTED event and wpa_cli sets this as WPA_ID_STR
	 * environment variable for action scripts.
	 */
	char *id_str;

#ifdef CONFIG_IEEE80211W
	/**
	 * ieee80211w - Whether management frame protection is enabled
	 *
	 * This value is used to configure policy for management frame
	 * protection (IEEE 802.11w). 0 = disabled, 1 = optional, 2 = required.
	 */
	enum mfp_options ieee80211w;
#endif /* CONFIG_IEEE80211W */

	/**
	 * frequency - Channel frequency in megahertz (MHz) for IBSS
	 *
	 * This value is used to configure the initial channel for IBSS (adhoc)
	 * networks, e.g., 2412 = IEEE 802.11b/g channel 1. It is ignored in
	 * the infrastructure mode. In addition, this value is only used by the
	 * station that creates the IBSS. If an IBSS network with the
	 * configured SSID is already present, the frequency of the network
	 * will be used instead of this configured value.
	 */
	int frequency;

	int ht40;

	/**
	 * wpa_ptk_rekey - Maximum lifetime for PTK in seconds
	 *
	 * This value can be used to enforce rekeying of PTK to mitigate some
	 * attacks against TKIP deficiencies.
	 */
	int wpa_ptk_rekey;

	/**
	 * scan_freq - Array of frequencies to scan or %NULL for all
	 *
	 * This is an optional zero-terminated array of frequencies in
	 * megahertz (MHz) to include in scan requests when searching for this
	 * network. This can be used to speed up scanning when the network is
	 * known to not use all possible channels.
	 */
	int *scan_freq;

	/**
	 * bgscan - Background scan and roaming parameters or %NULL if none
	 *
	 * This is an optional set of parameters for background scanning and
	 * roaming within a network (ESS) in following format:
	 * <bgscan module name>:<module parameters>
	 */
	char *bgscan;

	/**
	 * ignore_broadcast_ssid - Hide SSID in AP mode
	 *
	 * Send empty SSID in beacons and ignore probe request frames that do
	 * not specify full SSID, i.e., require stations to know SSID.
	 * default: disabled (0)
	 * 1 = send empty (length=0) SSID in beacon and ignore probe request
	 * for broadcast SSID
	 * 2 = clear SSID (ASCII 0), but keep the original length (this may be
	 * required with some clients that do not support empty SSID) and
	 * ignore probe requests for broadcast SSID
	 */
	int ignore_broadcast_ssid;

	/**
	 * freq_list - Array of allowed frequencies or %NULL for all
	 *
	 * This is an optional zero-terminated array of frequencies in
	 * megahertz (MHz) to allow for selecting the BSS. If set, scan results
	 * that do not match any of the specified frequencies are not
	 * considered when selecting a BSS.
	 */
	int *freq_list;

	/**
	 * p2p_client_list - List of P2P Clients in a persistent group (GO)
	 *
	 * This is a list of P2P Clients (P2P Device Address) that have joined
	 * the persistent group. This is maintained on the GO for persistent
	 * group entries (disabled == 2).
	 */
	u8 *p2p_client_list;

	/**
	 * num_p2p_clients - Number of entries in p2p_client_list
	 */
	size_t num_p2p_clients;

#ifndef P2P_MAX_STORED_CLIENTS
#define P2P_MAX_STORED_CLIENTS 100
#endif /* P2P_MAX_STORED_CLIENTS */

	/**
	 * p2p_group - Network generated as a P2P group (used internally)
	 */
	int p2p_group;

	/**
	 * p2p_persistent_group - Whether this is a persistent group
	 */
	int p2p_persistent_group;

	/**
	 * temporary - Whether this network is temporary and not to be saved
	 */
	int temporary;

	/**
	 * export_keys - Whether keys may be exported
	 *
	 * This attribute will be set when keys are determined through
	 * WPS or similar so that they may be exported.
	 */
	int export_keys;

#ifdef ANDROID_P2P
	/**
	 * assoc_retry - Number of times association should be retried.
	 */
	int assoc_retry;
#endif

#ifdef CONFIG_HT_OVERRIDES
	/**
	 * disable_ht - Disable HT (IEEE 802.11n) for this network
	 *
	 * By default, use it if it is available, but this can be configured
	 * to 1 to have it disabled.
	 */
	int disable_ht;

	/**
	 * disable_ht40 - Disable HT40 for this network
	 *
	 * By default, use it if it is available, but this can be configured
	 * to 1 to have it disabled.
	 */
	int disable_ht40;

	/**
	 * disable_max_amsdu - Disable MAX A-MSDU
	 *
	 * A-MDSU will be 3839 bytes when disabled, or 7935
	 * when enabled (assuming it is otherwise supported)
	 * -1 (default) means do not apply any settings to the kernel.
	 */
	int disable_max_amsdu;

	/**
	 * ampdu_factor - Maximum A-MPDU Length Exponent
	 *
	 * Value: 0-3, see 7.3.2.56.3 in IEEE Std 802.11n-2009.
	 */
	int ampdu_factor;

	/**
	 * ampdu_density - Minimum A-MPDU Start Spacing
	 *
	 * Value: 0-7, see 7.3.2.56.3 in IEEE Std 802.11n-2009.
	 */
	int ampdu_density;

	/**
	 * ht_mcs - Allowed HT-MCS rates, in ASCII hex: ffff0000...
	 *
	 * By default (empty string): Use whatever the OS has configured.
	 */
	char *ht_mcs;
#endif /* CONFIG_HT_OVERRIDES */

	/**
	 * ap_max_inactivity - Timeout in seconds to detect STA's inactivity
	 *
	 * This timeout value is used in AP mode to clean up inactive stations.
	 * By default: 300 seconds.
	 */
	int ap_max_inactivity;

	/**
	 * dtim_period - DTIM period in Beacon intervals
	 * By default: 2
	 */
	int dtim_period;

	/**
	 * auth_failures - Number of consecutive authentication failures
	 */
	unsigned int auth_failures;

	/**
	 * disabled_until - Network block disabled until this time if non-zero
	 */
	struct os_time disabled_until;
};

#endif /* CONFIG_SSID_H */
