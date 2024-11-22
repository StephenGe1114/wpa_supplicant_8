/*
 * Driver interface list
 * Copyright (c) 2004-2005, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"


#ifdef CONFIG_DRIVER_WEXT
extern struct wpa_driver_ops wpa_driver_wext_ops; /* driver_wext.c */
#endif /* CONFIG_DRIVER_WEXT */
#ifdef CONFIG_DRIVER_NL80211
extern struct wpa_driver_ops wpa_driver_nl80211_ops; /* driver_nl80211.c */
#endif /* CONFIG_DRIVER_NL80211 */
#ifdef CONFIG_DRIVER_HOSTAP
extern struct wpa_driver_ops wpa_driver_hostap_ops; /* driver_hostap.c */
#endif /* CONFIG_DRIVER_HOSTAP */
#ifdef CONFIG_DRIVER_MADWIFI
extern struct wpa_driver_ops wpa_driver_madwifi_ops; /* driver_madwifi.c */
#endif /* CONFIG_DRIVER_MADWIFI */
#ifdef CONFIG_DRIVER_BSD
extern struct wpa_driver_ops wpa_driver_bsd_ops; /* driver_bsd.c */
#endif /* CONFIG_DRIVER_BSD */
#ifdef CONFIG_DRIVER_NDIS
extern struct wpa_driver_ops wpa_driver_ndis_ops; /* driver_ndis.c */
#endif /* CONFIG_DRIVER_NDIS */
#ifdef CONFIG_DRIVER_WIRED
extern struct wpa_driver_ops wpa_driver_wired_ops; /* driver_wired.c */
#endif /* CONFIG_DRIVER_WIRED */
#ifdef CONFIG_DRIVER_TEST
extern struct wpa_driver_ops wpa_driver_test_ops; /* driver_test.c */
#endif /* CONFIG_DRIVER_TEST */
#ifdef CONFIG_DRIVER_ROBOSWITCH
/* driver_roboswitch.c */
extern struct wpa_driver_ops wpa_driver_roboswitch_ops;
#endif /* CONFIG_DRIVER_ROBOSWITCH */
#ifdef CONFIG_DRIVER_ATHEROS
extern struct wpa_driver_ops wpa_driver_atheros_ops; /* driver_atheros.c */
#endif /* CONFIG_DRIVER_ATHEROS */
#ifdef CONFIG_DRIVER_NONE
extern struct wpa_driver_ops wpa_driver_none_ops; /* driver_none.c */
#endif /* CONFIG_DRIVER_NONE */

// wpa_drivers数组成员指向一个wpa_driver_ops类型的对象。wpa_driver_ops是driver i/f模块的核心数据结构，其内部定义了很多函数指针。而正是通过定义函数指针的方法，WPAS能够隔离上层使用者和具体的driver。
// 此处的driver并非通常意义所指的那些运行于Kernel层的驱动。读者可认为它们是Kernel层wlan驱动在用户空间的代理模块。上层使用者通过它们来和Kernel层的驱动交互。为了避免混淆，本书后续将用driver wrapper一词来表示WPAS中的driver。而driver一词将专指Kernel里对应的wlan驱动。
struct wpa_driver_ops *wpa_drivers[] =
{
#ifdef CONFIG_DRIVER_WEXT
	&wpa_driver_wext_ops,
#endif /* CONFIG_DRIVER_WEXT */
#ifdef CONFIG_DRIVER_NL80211
	&wpa_driver_nl80211_ops,
#endif /* CONFIG_DRIVER_NL80211 */
#ifdef CONFIG_DRIVER_HOSTAP
	&wpa_driver_hostap_ops,
#endif /* CONFIG_DRIVER_HOSTAP */
#ifdef CONFIG_DRIVER_MADWIFI
	&wpa_driver_madwifi_ops,
#endif /* CONFIG_DRIVER_MADWIFI */
#ifdef CONFIG_DRIVER_BSD
	&wpa_driver_bsd_ops,
#endif /* CONFIG_DRIVER_BSD */
#ifdef CONFIG_DRIVER_NDIS
	&wpa_driver_ndis_ops,
#endif /* CONFIG_DRIVER_NDIS */
#ifdef CONFIG_DRIVER_WIRED
	&wpa_driver_wired_ops,
#endif /* CONFIG_DRIVER_WIRED */
#ifdef CONFIG_DRIVER_TEST
	&wpa_driver_test_ops,
#endif /* CONFIG_DRIVER_TEST */
#ifdef CONFIG_DRIVER_ROBOSWITCH
	&wpa_driver_roboswitch_ops,
#endif /* CONFIG_DRIVER_ROBOSWITCH */
#ifdef CONFIG_DRIVER_ATHEROS
	&wpa_driver_atheros_ops,
#endif /* CONFIG_DRIVER_ATHEROS */
#ifdef CONFIG_DRIVER_NONE
	&wpa_driver_none_ops,
#endif /* CONFIG_DRIVER_NONE */
	NULL
};
