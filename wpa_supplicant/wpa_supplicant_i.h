/*
 * wpa_supplicant - Internal definitions
 * Copyright (c) 2003-2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef WPA_SUPPLICANT_I_H
#define WPA_SUPPLICANT_I_H

#include "utils/list.h"
#include "common/defs.h"
#include "config_ssid.h"

extern const char *wpa_supplicant_version;
extern const char *wpa_supplicant_license;
#ifndef CONFIG_NO_STDOUT_DEBUG
extern const char *wpa_supplicant_full_license1;
extern const char *wpa_supplicant_full_license2;
extern const char *wpa_supplicant_full_license3;
extern const char *wpa_supplicant_full_license4;
extern const char *wpa_supplicant_full_license5;
#endif /* CONFIG_NO_STDOUT_DEBUG */

struct wpa_sm;
struct wpa_supplicant;
struct ibss_rsn;
struct scan_info;
struct wpa_bss;
struct wpa_scan_results;
struct hostapd_hw_modes;
struct wpa_driver_associate_params;

/*
 * Forward declarations of private structures used within the ctrl_iface
 * backends. Other parts of wpa_supplicant do not have access to data stored in
 * these structures.
 */
struct ctrl_iface_priv;
struct ctrl_iface_global_priv;
struct wpas_dbus_priv;

/**
 * struct wpa_interface - Parameters for wpa_supplicant_add_iface()
 */
struct wpa_interface { // 用于描述一个无线网络设备。该参数在初始化时用到
	/**
	 * confname - Configuration name (file or profile) name
	 *
	 * This can also be %NULL when a configuration file is not used. In
	 * that case, ctrl_interface must be set to allow the interface to be
	 * configured.
	 */
	const char *confname; // 该接口对应的配置文件名

	/**
	 * ctrl_interface - Control interface parameter
	 *
	 * If a configuration file is not used, this variable can be used to
	 * set the ctrl_interface parameter that would have otherwise been read
	 * from the configuration file. If both confname and ctrl_interface are
	 * set, ctrl_interface is used to override the value from configuration
	 * file.
	 */
	const char *ctrl_interface; // 控制接口unix域socket地址

	/**
	 * driver - Driver interface name, or %NULL to use the default driver
	 */
	const char *driver; // 该接口对应驱动的参数

	/**
	 * driver_param - Driver interface parameters
	 *
	 * If a configuration file is not used, this variable can be used to
	 * set the driver_param parameters that would have otherwise been read
	 * from the configuration file. If both confname and driver_param are
	 * set, driver_param is used to override the value from configuration
	 * file.
	 */
	const char *driver_param;

	/**
	 * ifname - Interface name
	 */
	const char *ifname; // 指定网络接口设备名

	/**
	 * bridge_ifname - Optional bridge interface name
	 *
	 * If the driver interface (ifname) is included in a Linux bridge
	 * device, the bridge interface may need to be used for receiving EAPOL
	 * frames. This can be enabled by setting this variable to enable
	 * receiving of EAPOL frames from an additional interface.
	 */
	const char *bridge_ifname; // 当接口用作桥接设备时，其桥接设备名
};

/**
 * struct wpa_params - Parameters for wpa_supplicant_init()
 */
struct wpa_params {
	/**
	 * daemonize - Run %wpa_supplicant in the background
	 */
	int daemonize;

	/**
	 * wait_for_monitor - Wait for a monitor program before starting
	 */
	int wait_for_monitor;

	/**
	 * pid_file - Path to a PID (process ID) file
	 *
	 * If this and daemonize are set, process ID of the background process
	 * will be written to the specified file.
	 */
	char *pid_file;

	/**
	 * wpa_debug_level - Debugging verbosity level (e.g., MSG_INFO)
	 */
	int wpa_debug_level;

	/**
	 * wpa_debug_show_keys - Whether keying material is included in debug
	 *
	 * This parameter can be used to allow keying material to be included
	 * in debug messages. This is a security risk and this option should
	 * not be enabled in normal configuration. If needed during
	 * development or while troubleshooting, this option can provide more
	 * details for figuring out what is happening.
	 */
	int wpa_debug_show_keys;

	/**
	 * wpa_debug_timestamp - Whether to include timestamp in debug messages
	 */
	int wpa_debug_timestamp;

	/**
	 * ctrl_interface - Global ctrl_iface path/parameter
	 */
	char *ctrl_interface;

	/**
	 * dbus_ctrl_interface - Enable the DBus control interface
	 */
	int dbus_ctrl_interface;

	/**
	 * wpa_debug_file_path - Path of debug file or %NULL to use stdout
	 */
	const char *wpa_debug_file_path;

	/**
	 * wpa_debug_syslog - Enable log output through syslog
	 */
	int wpa_debug_syslog;

	/**
	 * wpa_debug_tracing - Enable log output through Linux tracing
	 */
	int wpa_debug_tracing;

	/**
	 * override_driver - Optional driver parameter override
	 *
	 * This parameter can be used to override the driver parameter in
	 * dynamic interface addition to force a specific driver wrapper to be
	 * used instead.
	 */
	char *override_driver;

	/**
	 * override_ctrl_interface - Optional ctrl_interface override
	 *
	 * This parameter can be used to override the ctrl_interface parameter
	 * in dynamic interface addition to force a control interface to be
	 * created.
	 */
	char *override_ctrl_interface;

	/**
	 * entropy_file - Optional entropy file
	 *
	 * This parameter can be used to configure wpa_supplicant to maintain
	 * its internal entropy store over restarts.
	 */
	char *entropy_file;
};

struct p2p_srv_bonjour {
	struct dl_list list;
	struct wpabuf *query;
	struct wpabuf *resp;
};

struct p2p_srv_upnp {
	struct dl_list list;
	u8 version;
	char *service;
};

struct wpa_freq_range {
	unsigned int min;
	unsigned int max;
};


/**
 * struct wpa_global - Internal, global data for all %wpa_supplicant interfaces
 *
 * This structure is initialized by calling wpa_supplicant_init() when starting
 * %wpa_supplicant.
 */
struct wpa_global { // 一个全局性质的上下文信息
    // 它通过ifaces变量指向一个wpa_supplicant对象（以后介绍wpa_supplicant时，读者将发现系统内的所有wpa_supplicant对象将通过单向链表连接在一起。所以，严格意义上来说，ifaces变量指向一个wpa_supplicant对象链表）。
	// wpa_supplicant是WPAS的核心数据结构。一个interface对应有一个wpa_supplicant对象，其内部包含非常多的成员变量（图4-7并未画出，下文详细介绍）。另外，系统中所有wpa_supplicant对象都通过next变量链接在一起
	struct wpa_supplicant *ifaces;
	struct wpa_params params; // 运行参数
	// 全局控制接口，如果设置该接口，其他wpa_interface设置的控制接口将被替代
	// 全局控制接口的信息，内部包含一个用于通信的socket句柄
	struct ctrl_iface_global_priv *ctrl_iface; 
	struct wpas_dbus_priv *dbus;
	void **drv_priv; // driver wrapper对应的全局上下文信息
	size_t drv_count; // driver wrapper的个数
	struct os_time suspend_time;
	struct p2p_data *p2p;
	struct wpa_supplicant *p2p_init_wpa_s;
	struct wpa_supplicant *p2p_group_formation;
	u8 p2p_dev_addr[ETH_ALEN];
	struct dl_list p2p_srv_bonjour; /* struct p2p_srv_bonjour */
	struct dl_list p2p_srv_upnp; /* struct p2p_srv_upnp */
	int p2p_disabled;
	int cross_connection;
	struct wpa_freq_range *p2p_disallow_freq;
	unsigned int num_p2p_disallow_freq;
	enum wpa_conc_pref {
		WPA_CONC_PREF_NOT_SET,
		WPA_CONC_PREF_STA,
		WPA_CONC_PREF_P2P
	} conc_pref;
	unsigned int p2p_cb_on_scan_complete:1;

#ifdef CONFIG_WIFI_DISPLAY
	int wifi_display;
#define MAX_WFD_SUBELEMS 10
	struct wpabuf *wfd_subelem[MAX_WFD_SUBELEMS];
#endif /* CONFIG_WIFI_DISPLAY */
};


enum offchannel_send_action_result {
	OFFCHANNEL_SEND_ACTION_SUCCESS /* Frame was send and acknowledged */,
	OFFCHANNEL_SEND_ACTION_NO_ACK /* Frame was sent, but not acknowledged
				       */,
	OFFCHANNEL_SEND_ACTION_FAILED /* Frame was not sent due to a failure */
};

struct wps_ap_info {
	u8 bssid[ETH_ALEN];
	enum wps_ap_info_type {
		WPS_AP_NOT_SEL_REG,
		WPS_AP_SEL_REG,
		WPS_AP_SEL_REG_OUR
	} type;
	unsigned int tries;
	struct os_time last_attempt;
};

/**
 * struct wpa_supplicant - Internal data for wpa_supplicant interface
 *
 * This structure contains the internal data for core wpa_supplicant code. This
 * should be only used directly from the core code. However, a pointer to this
 * data is used from other files as an arbitrary context pointer in calls to
 * core functions.
 */
struct wpa_supplicant {
	struct wpa_global *global; 
	struct wpa_supplicant *parent;
	struct wpa_supplicant *next; // 进程内所有的wpa_supplicant对象都保存在一个单链表中
	struct l2_packet_data *l2; // 用于处理EAP和EAPOL消息，L2是Link Layer的简写
	struct l2_packet_data *l2_br; 
	unsigned char own_addr[ETH_ALEN];
	char ifname[100];
#ifdef CONFIG_CTRL_IFACE_DBUS
	char *dbus_path;
#endif /* CONFIG_CTRL_IFACE_DBUS */
#ifdef CONFIG_CTRL_IFACE_DBUS_NEW
	char *dbus_new_path;
	char *dbus_groupobj_path;
#ifdef CONFIG_AP
	char *preq_notify_peer;
#endif /* CONFIG_AP */
#endif /* CONFIG_CTRL_IFACE_DBUS_NEW */
	char bridge_ifname[16];

	char *confname; // 运行时配置文件名，本例是/data/misc/wifi/wpa_supplicant.conf
	struct wpa_config *conf; // 解析运行时配置文件后得到的配置信息
	/*该变量名可译为“策略”，和TKIP的MIC（Message Integrity Check，消息完整性校验）有关。因为TKIP MIC所使用的Michael算法在某些情况下容易被攻破，所以规范特别定义了TKIP MIC countermeasures用于处理这类事情。例如，一旦检测到60秒内发生两次以上MIC错误，则停止TKIP通信60秒*/
	int countermeasures;
	os_time_t last_michael_mic_error;
	u8 bssid[ETH_ALEN]; // 表示此supplicant链接到的无线网络的BSSID
	// 当supplicant还处于关联过程中时,该变量保存目标
	u8 pending_bssid[ETH_ALEN]; /* If wpa_state == WPA_ASSOCIATING, this
				     * field contains the target BSSID. */
	// 是否重新关联
	int reassociate; /* reassociation requested */
	// 此supplicant是否被禁止链接无线网络
	int disconnected; /* all connections disabled; i.e., do no reassociate
			   * before this has been cleared */
	struct wpa_ssid *current_ssid; // 当前使用的wpa_ssid对象
	/*wpa_bss是无线网络在wpa_supplicant中的代表。wpa_bss中的成员主要描述了无线网络的bssid、ssid、频率（freq，以MHz为单位）、Beacon心跳时间（以TU为单位）、capability信息（网络性能，见3.3.5节定长字段介绍）、信号强度等。wpa_bss的作用很重要，不过其数据结构相对比较简单*/
	struct wpa_bss *current_bss; // 当前使用的wpa_bss对象
	int ap_ies_from_associnfo;
	unsigned int assoc_freq;

	/* Selected configuration (based on Beacon/ProbeResp WPA IE) */
	/*这几个变量表示该wpa_supplicant最终选择的安全策略。其中mgmt_group_cipher和IEEE 802.11w（定义了管理帧加密的规范）有关*/
	int pairwise_cipher; // 此supplicant选择的单播数据加密类型
	int group_cipher;
	int key_mgmt;
	int wpa_proto;
	int mgmt_group_cipher;

    /*WPAS为driver wrapper一共定义了两个上下文信息。这是因为driver i/f接口定义了两个初始化函数（以nl80211 driver为例，它们分别是global_init和init2）。其中，global_init返回值为driver wrapper全局上下文信息，它将保存在wpa_global的drv_priv数组中（见图4-7）。每个wpa_supplicant都对应有一个driver wrapper对象，故它也需要保存对应的全局上下文信息。init2返回值则是driver wrapper上下文信息，它保存在wpa_supplicant的driv_priv中*/
    // 驱动对应的上下文信息
	void *drv_priv; /* private data used by driver_ops */
	void *global_drv_priv; // 驱动对应的全局上下文信息

	u8 *bssid_filter;
	size_t bssid_filter_count;

	/* previous scan was wildcard when interleaving between
	 * wildcard scans and specific SSID scan when max_ssids=1 */
	int prev_scan_wildcard;
	struct wpa_ssid *prev_scan_ssid; /* previously scanned SSID;
					  * NULL = not yet initialized (start
					  * with wildcard SSID)
					  * WILDCARD_SSID_SCAN = wildcard
					  * SSID was used in the previous scan
					  */
#define WILDCARD_SSID_SCAN ((struct wpa_ssid *) 1)

	struct wpa_ssid *prev_sched_ssid; /* last SSID used in sched scan */
	/*该变量和计划扫描（scheduled scan）功能有关。计划扫描即定时扫描，需要Kernel（版本必须大于3.0）的Wi-Fi驱动支持。启用该功能时，需要为驱动设置定时扫描的间隔（以毫秒为单位）*/
	int sched_scan_timeout; // 和scheduled(计划)扫描功能有关
	int sched_scan_interval; 
	int first_sched_scan;
	int sched_scan_timed_out;

	void (*scan_res_handler)(struct wpa_supplicant *wpa_s,
				 struct wpa_scan_results *scan_res);
	// 保存此supplicant搜索到的周围的无线网络(由wpa_bss对象表示)
	struct dl_list bss; /* struct wpa_bss::list */
	struct dl_list bss_id; /* struct wpa_bss::list_id */
	size_t num_bss;
	unsigned int bss_update_idx;
	unsigned int bss_next_id;

	 /*
	  * Pointers to BSS entries in the order they were in the last scan
	  * results.
	  */
	struct wpa_bss **last_scan_res;
	unsigned int last_scan_res_used;
	unsigned int last_scan_res_size;
	int last_scan_full;
	struct os_time last_scan;

	struct wpa_driver_ops *driver; // 此supplicant对应的驱动对象
	int interface_removed; /* whether the network interface has been
				* removed */
	struct wpa_sm *wpa; // wpa状态机
	struct eapol_sm *eapol;

	struct ctrl_iface_priv *ctrl_iface; // 此supplicant对应的控制接口对象

	enum wpa_states wpa_state; // supplicant当前的状态
	int scanning;
	int sched_scanning;
	int new_connection;
	int reassociated_connection;

	int eapol_received; /* number of EAPOL packets received after the
			     * previous association event */

	struct scard_data *scard;
#ifdef PCSC_FUNCS
	char imsi[20];
	int mnc_len;
#endif /* PCSC_FUNCS */

	unsigned char last_eapol_src[ETH_ALEN];

	int keys_cleared;

	struct wpa_blacklist *blacklist; // 黑名单.supplicant将不会连接黑名单中的无线网络

	int scan_req; /* manual scan request; this forces a scan even if there
		       * are no enabled networks in the configuration */
	int scan_runs; /* number of scan runs since WPS was started */
	int *next_scan_freqs;
	int scan_interval; /* time in sec between scans to find suitable AP */
	int normal_scans; /* normal scans run before sched_scan */

	unsigned int drv_flags;
	unsigned int drv_enc;

	/*
	 * A bitmap of supported protocols for probe response offload. See
	 * struct wpa_driver_capa in driver.h
	 */
	unsigned int probe_resp_offloads;

	int max_scan_ssids;
	int max_sched_scan_ssids;
	int sched_scan_supported;
	unsigned int max_match_sets;
	unsigned int max_remain_on_chan;
	unsigned int max_stations;

	int pending_mic_error_report;
	int pending_mic_error_pairwise;
	int mic_errors_seen; /* Michael MIC errors with the current PTK */

	struct wps_context *wps;
	int wps_success; /* WPS success event received */
	struct wps_er *wps_er;
	int blacklist_cleared;

	struct wpabuf *pending_eapol_rx;
	struct os_time pending_eapol_rx_time;
	u8 pending_eapol_rx_src[ETH_ALEN];

	struct ibss_rsn *ibss_rsn;

	int set_sta_uapsd;
	int sta_uapsd;
	int set_ap_uapsd;
	int ap_uapsd;

/*该变量是一个编译宏，用于设置WPAS是否支持SME。我们在3.3.6节“802.11 MAC管理实体”中曾介绍过SME（Station Management Entity）。如果该功能支持，则driver wrapper可直接利用SME定义的SAP，而无须使用MLME的SAP了。Android平台中如果定义了CONFIG_DRIVER_NL80211宏，则CONFIG_SME也将被定义（参考drivers.mk文件）。不过SME的功能是否起作用，还需要看driver是否支持*/
#ifdef CONFIG_SME
	struct {
		u8 ssid[32];
		size_t ssid_len;
		int freq;
		u8 assoc_req_ie[200];
		size_t assoc_req_ie_len;
		int mfp;
		int ft_used;
		u8 mobility_domain[2];
		u8 *ft_ies;
		size_t ft_ies_len;
		u8 prev_bssid[ETH_ALEN];
		int prev_bssid_set;
		int auth_alg;
		int proto;

		int sa_query_count; /* number of pending SA Query requests;
				     * 0 = no SA Query in progress */
		int sa_query_timed_out;
		u8 *sa_query_trans_id; /* buffer of WLAN_SA_QUERY_TR_ID_LEN *
					* sa_query_count octets of pending
					* SA Query transaction identifiers */
		struct os_time sa_query_start;
		u8 sched_obss_scan;
		u16 obss_scan_int;
		u16 bss_max_idle_period;
	} sme;
#endif /* CONFIG_SME */

#ifdef CONFIG_AP
	struct hostapd_iface *ap_iface;
	void (*ap_configured_cb)(void *ctx, void *data);
	void *ap_configured_cb_ctx;
	void *ap_configured_cb_data;
#endif /* CONFIG_AP */

	unsigned int off_channel_freq;
	struct wpabuf *pending_action_tx;
	u8 pending_action_src[ETH_ALEN];
	u8 pending_action_dst[ETH_ALEN];
	u8 pending_action_bssid[ETH_ALEN];
	unsigned int pending_action_freq;
	int pending_action_no_cck;
	int pending_action_without_roc;
	void (*pending_action_tx_status_cb)(struct wpa_supplicant *wpa_s,
					    unsigned int freq, const u8 *dst,
					    const u8 *src, const u8 *bssid,
					    const u8 *data, size_t data_len,
					    enum offchannel_send_action_result
					    result);
	unsigned int roc_waiting_drv_freq;
	int action_tx_wait_time;

#ifdef CONFIG_P2P
	struct p2p_go_neg_results *go_params;
	int create_p2p_iface;
	u8 pending_interface_addr[ETH_ALEN];
	char pending_interface_name[100];
	int pending_interface_type;
	int p2p_group_idx;
	unsigned int pending_listen_freq;
	unsigned int pending_listen_duration;
	enum {
		NOT_P2P_GROUP_INTERFACE,
		P2P_GROUP_INTERFACE_PENDING,
		P2P_GROUP_INTERFACE_GO,
		P2P_GROUP_INTERFACE_CLIENT
	} p2p_group_interface;
	struct p2p_group *p2p_group;
	int p2p_long_listen; /* remaining time in long Listen state in ms */
	char p2p_pin[10];
	int p2p_wps_method;
	u8 p2p_auth_invite[ETH_ALEN];
	int p2p_sd_over_ctrl_iface;
	int p2p_in_provisioning;
	int pending_invite_ssid_id;
	int show_group_started;
	u8 go_dev_addr[ETH_ALEN];
	int pending_pd_before_join;
	u8 pending_join_iface_addr[ETH_ALEN];
	u8 pending_join_dev_addr[ETH_ALEN];
	int pending_join_wps_method;
	int p2p_join_scan_count;
	int auto_pd_scan_retry;
	int force_long_sd;
	u16 pending_pd_config_methods;
	enum {
		NORMAL_PD, AUTO_PD_GO_NEG, AUTO_PD_JOIN
	} pending_pd_use;

	/*
	 * Whether cross connection is disallowed by the AP to which this
	 * interface is associated (only valid if there is an association).
	 */
	int cross_connect_disallowed;

	/*
	 * Whether this P2P group is configured to use cross connection (only
	 * valid if this is P2P GO interface). The actual cross connect packet
	 * forwarding may not be configured depending on the uplink status.
	 */
	int cross_connect_enabled;

	/* Whether cross connection forwarding is in use at the moment. */
	int cross_connect_in_use;

	/*
	 * Uplink interface name for cross connection
	 */
	char cross_connect_uplink[100];

	unsigned int sta_scan_pending:1;
	unsigned int p2p_auto_join:1;
	unsigned int p2p_auto_pd:1;
	unsigned int p2p_persistent_group:1;
	unsigned int p2p_fallback_to_go_neg:1;
	unsigned int p2p_pd_before_go_neg:1;
	unsigned int p2p_go_ht40:1;
	int p2p_persistent_go_freq;
	int p2p_persistent_id;
	int p2p_go_intent;
	int p2p_connect_freq;
	struct os_time p2p_auto_started;
#endif /* CONFIG_P2P */

	struct wpa_ssid *bgscan_ssid;
	/*该变量和后台扫描及漫游（background scan and roaming）技术有关。当STA在ESS（假设该ESS由多个AP共同构成）中移动时，有时候因为信号不好（例如STA离之前所关联的AP距离过远等），它需要切换到另外一个距离更近（即信号更好）的AP。这个切换AP的工作就是所谓的漫游。为了增强切换AP时的无缝体验（扫描过程中，STA不能收发数据帧。从用户角度来看，相当于网络不能使用），STA可采用background scan（定时扫描一小段时间或者当网络空闲时才扫描，这样可减少对用户正常使用的干扰）技术来监视周围AP的信号强度等信息。一旦之前使用的AP信号强度低于某个阈值，STA则可快速切换到某个信号更强的AP。除了background scan外，还有一种on-roam scan也能提升AP切换时的无缝体验*/
	const struct bgscan_ops *bgscan; // background扫描功能
	void *bgscan_priv;

	const struct autoscan_ops *autoscan;
	struct wpa_driver_scan_params *autoscan_params;
	void *autoscan_priv;

	struct wpa_ssid *connect_without_scan;

	struct wps_ap_info *wps_ap;
	size_t num_wps_ap;
	int wps_ap_iter;

	int after_wps;
	int known_wps_freq;
	unsigned int wps_freq;
	int wps_fragment_size;
	int auto_reconnect_disabled;

	 /* Channel preferences for AP/P2P GO use */
	int best_24_freq;
	int best_5_freq;
	int best_overall_freq;

    /*该变量是GAS（Generic Advertisement Service，通用广告服务）的小写，和802.11u协议有关。该协议规定了不同网络间互操作的标准，其制定的初衷是希望Wi-Fi网络能够像运营商的蜂窝网络一样，方便终端设备接入。例如，人们用智能手机可搜索到数十个、甚至上百个无线网络。在这种情况下如何选择正确的无线网络呢？802.11u协议使用GAS和ANQP（AccessNetwork Query Protocol，接入网络查询协议）来帮助设备自动选择合适的无线网络。其中，GAS是MLME SAP中的一种（见规范6.3.71节），它使得STA在通过认证前（prior to authentication）就可以向AP发送和接收ANQP数据包。STA则使用ANQP协议向AP查询无线网络运营商的信息，然后STA根据这些信息来判断自己可以加入哪一个运营商的无线网络（例如中国移动手机卡用户可以连接中国移动架设的无线网络）。*/
	struct gas_query *gas; // 和GAS功能有关

#ifdef CONFIG_INTERWORKING
	unsigned int fetch_anqp_in_progress:1;
	unsigned int network_select:1;
	unsigned int auto_select:1;
	unsigned int auto_network_select:1;
	unsigned int fetch_all_anqp:1;
#endif /* CONFIG_INTERWORKING */
	unsigned int drv_capa_known;

	struct {
		struct hostapd_hw_modes *modes;
		u16 num_modes;
		u16 flags;
	} hw;

	int pno;

	/* WLAN_REASON_* reason codes. Negative if locally generated. */
	int disconnect_reason;

	struct ext_password_data *ext_pw;

	struct wpabuf *last_gas_resp;
	u8 last_gas_addr[ETH_ALEN];
	u8 last_gas_dialog_token;
};


/* wpa_supplicant.c */
void wpa_supplicant_apply_ht_overrides(
	struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid,
	struct wpa_driver_associate_params *params);

int wpa_set_wep_keys(struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid);

int wpa_supplicant_reload_configuration(struct wpa_supplicant *wpa_s);

const char * wpa_supplicant_state_txt(enum wpa_states state);
int wpa_supplicant_update_mac_addr(struct wpa_supplicant *wpa_s);
int wpa_supplicant_driver_init(struct wpa_supplicant *wpa_s);
int wpa_supplicant_set_suites(struct wpa_supplicant *wpa_s,
			      struct wpa_bss *bss, struct wpa_ssid *ssid,
			      u8 *wpa_ie, size_t *wpa_ie_len);
void wpa_supplicant_associate(struct wpa_supplicant *wpa_s,
			      struct wpa_bss *bss,
			      struct wpa_ssid *ssid);
void wpa_supplicant_set_non_wpa_policy(struct wpa_supplicant *wpa_s,
				       struct wpa_ssid *ssid);
void wpa_supplicant_initiate_eapol(struct wpa_supplicant *wpa_s);
void wpa_clear_keys(struct wpa_supplicant *wpa_s, const u8 *addr);
void wpa_supplicant_req_auth_timeout(struct wpa_supplicant *wpa_s,
				     int sec, int usec);
void wpa_supplicant_reinit_autoscan(struct wpa_supplicant *wpa_s);
void wpa_supplicant_set_state(struct wpa_supplicant *wpa_s,
			      enum wpa_states state);
struct wpa_ssid * wpa_supplicant_get_ssid(struct wpa_supplicant *wpa_s);
const char * wpa_supplicant_get_eap_mode(struct wpa_supplicant *wpa_s);
void wpa_supplicant_cancel_auth_timeout(struct wpa_supplicant *wpa_s);
void wpa_supplicant_deauthenticate(struct wpa_supplicant *wpa_s,
				   int reason_code);
void wpa_supplicant_disassociate(struct wpa_supplicant *wpa_s,
				 int reason_code);

void wpa_supplicant_enable_network(struct wpa_supplicant *wpa_s,
				   struct wpa_ssid *ssid);
void wpa_supplicant_disable_network(struct wpa_supplicant *wpa_s,
				    struct wpa_ssid *ssid);
void wpa_supplicant_select_network(struct wpa_supplicant *wpa_s,
				   struct wpa_ssid *ssid);
int wpa_supplicant_set_ap_scan(struct wpa_supplicant *wpa_s,
			       int ap_scan);
int wpa_supplicant_set_bss_expiration_age(struct wpa_supplicant *wpa_s,
					  unsigned int expire_age);
int wpa_supplicant_set_bss_expiration_count(struct wpa_supplicant *wpa_s,
					    unsigned int expire_count);
int wpa_supplicant_set_scan_interval(struct wpa_supplicant *wpa_s,
				     int scan_interval);
int wpa_supplicant_set_debug_params(struct wpa_global *global,
				    int debug_level, int debug_timestamp,
				    int debug_show_keys);
void free_hw_features(struct wpa_supplicant *wpa_s);

void wpa_show_license(void);

struct wpa_supplicant * wpa_supplicant_add_iface(struct wpa_global *global,
						 struct wpa_interface *iface);
int wpa_supplicant_remove_iface(struct wpa_global *global,
				struct wpa_supplicant *wpa_s,
				int terminate);
struct wpa_supplicant * wpa_supplicant_get_iface(struct wpa_global *global,
						 const char *ifname);
struct wpa_global * wpa_supplicant_init(struct wpa_params *params);
int wpa_supplicant_run(struct wpa_global *global);
void wpa_supplicant_deinit(struct wpa_global *global);

int wpa_supplicant_scard_init(struct wpa_supplicant *wpa_s,
			      struct wpa_ssid *ssid);
void wpa_supplicant_terminate_proc(struct wpa_global *global);
void wpa_supplicant_rx_eapol(void *ctx, const u8 *src_addr,
			     const u8 *buf, size_t len);
enum wpa_key_mgmt key_mgmt2driver(int key_mgmt);
enum wpa_cipher cipher_suite2driver(int cipher);
void wpa_supplicant_update_config(struct wpa_supplicant *wpa_s);
void wpa_supplicant_clear_status(struct wpa_supplicant *wpa_s);
void wpas_connection_failed(struct wpa_supplicant *wpa_s, const u8 *bssid);
int wpas_driver_bss_selection(struct wpa_supplicant *wpa_s);
int wpas_is_p2p_prioritized(struct wpa_supplicant *wpa_s);
void wpas_auth_failed(struct wpa_supplicant *wpa_s);
void wpas_clear_temp_disabled(struct wpa_supplicant *wpa_s,
			      struct wpa_ssid *ssid, int clear_failures);
void wpa_supplicant_proc_40mhz_intolerant(struct wpa_supplicant *wpa_s);

/**
 * wpa_supplicant_ctrl_iface_ctrl_rsp_handle - Handle a control response
 * @wpa_s: Pointer to wpa_supplicant data
 * @ssid: Pointer to the network block the reply is for
 * @field: field the response is a reply for
 * @value: value (ie, password, etc) for @field
 * Returns: 0 on success, non-zero on error
 *
 * Helper function to handle replies to control interface requests.
 */
int wpa_supplicant_ctrl_iface_ctrl_rsp_handle(struct wpa_supplicant *wpa_s,
					      struct wpa_ssid *ssid,
					      const char *field,
					      const char *value);

/* events.c */
void wpa_supplicant_mark_disassoc(struct wpa_supplicant *wpa_s);
int wpa_supplicant_connect(struct wpa_supplicant *wpa_s,
			   struct wpa_bss *selected,
			   struct wpa_ssid *ssid);
void wpa_supplicant_stop_countermeasures(void *eloop_ctx, void *sock_ctx);
void wpa_supplicant_delayed_mic_error_report(void *eloop_ctx, void *sock_ctx);
void wnm_bss_keep_alive_deinit(struct wpa_supplicant *wpa_s);
int wpas_select_network_from_last_scan(struct wpa_supplicant *wpa_s);

/* eap_register.c */
int eap_register_methods(void);

/**
 * Utility method to tell if a given network is a persistent group
 * @ssid: Network object
 * Returns: 1 if network is a persistent group, 0 otherwise
 */
static inline int network_is_persistent_group(struct wpa_ssid *ssid)
{
	return ((ssid->disabled == 2) || ssid->p2p_persistent_group);
}

int wpas_network_disabled(struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid);

int wpas_init_ext_pw(struct wpa_supplicant *wpa_s);

#endif /* WPA_SUPPLICANT_I_H */
