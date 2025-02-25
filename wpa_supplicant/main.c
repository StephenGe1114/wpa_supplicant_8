/*
 * WPA Supplicant / main() function for UNIX like OSes and MinGW
 * Copyright (c) 2003-2007, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#ifdef __linux__
#include <fcntl.h>
#endif /* __linux__ */

#include "common.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"

extern struct wpa_driver_ops *wpa_drivers[];


static void usage(void)
{
	int i;
	printf("%s\n\n%s\n"
	       "usage:\n"
	       "  wpa_supplicant [-BddhKLqqstuvW] [-P<pid file>] "
	       "[-g<global ctrl>] \\\n"
	       "        -i<ifname> -c<config file> [-C<ctrl>] [-D<driver>] "
	       "[-p<driver_param>] \\\n"
	       "        [-b<br_ifname>] [-f<debug file>] [-e<entropy file>] "
	       "\\\n"
	       "        [-o<override driver>] [-O<override ctrl>] \\\n"
	       "        [-N -i<ifname> -c<conf> [-C<ctrl>] "
	       "[-D<driver>] \\\n"
	       "        [-p<driver_param>] [-b<br_ifname>] ...]\n"
	       "\n"
	       "drivers:\n",
	       wpa_supplicant_version, wpa_supplicant_license);

	for (i = 0; wpa_drivers[i]; i++) {
		printf("  %s = %s\n",
		       wpa_drivers[i]->name,
		       wpa_drivers[i]->desc);
	}

#ifndef CONFIG_NO_STDOUT_DEBUG
	printf("options:\n"
	       "  -b = optional bridge interface name\n"
	       "  -B = run daemon in the background\n"
	       "  -c = Configuration file\n"
	       "  -C = ctrl_interface parameter (only used if -c is not)\n"
	       "  -i = interface name\n"
	       "  -d = increase debugging verbosity (-dd even more)\n"
	       "  -D = driver name (can be multiple drivers: nl80211,wext)\n"
	       "  -e = entropy file\n");
#ifdef CONFIG_DEBUG_FILE
	printf("  -f = log output to debug file instead of stdout\n");
#endif /* CONFIG_DEBUG_FILE */
	printf("  -g = global ctrl_interface\n"
	       "  -K = include keys (passwords, etc.) in debug output\n");
#ifdef CONFIG_DEBUG_SYSLOG
	printf("  -s = log output to syslog instead of stdout\n");
#endif /* CONFIG_DEBUG_SYSLOG */
#ifdef CONFIG_DEBUG_LINUX_TRACING
	printf("  -T = record to Linux tracing in addition to logging\n");
	printf("       (records all messages regardless of debug verbosity)\n");
#endif /* CONFIG_DEBUG_LINUX_TRACING */
	printf("  -t = include timestamp in debug messages\n"
	       "  -h = show this help text\n"
	       "  -L = show license (BSD)\n"
	       "  -o = override driver parameter for new interfaces\n"
	       "  -O = override ctrl_interface parameter for new interfaces\n"
	       "  -p = driver parameters\n"
	       "  -P = PID file\n"
	       "  -q = decrease debugging verbosity (-qq even less)\n");
#ifdef CONFIG_DBUS
	printf("  -u = enable DBus control interface\n");
#endif /* CONFIG_DBUS */
	printf("  -v = show version\n"
	       "  -W = wait for a control interface monitor before starting\n"
	       "  -N = start describing new interface\n");

	printf("example:\n"
	       "  wpa_supplicant -D%s -iwlan0 -c/etc/wpa_supplicant.conf\n",
	       wpa_drivers[i] ? wpa_drivers[i]->name : "wext");
#endif /* CONFIG_NO_STDOUT_DEBUG */
}


static void license(void)
{
#ifndef CONFIG_NO_STDOUT_DEBUG
	printf("%s\n\n%s%s%s%s%s\n",
	       wpa_supplicant_version,
	       wpa_supplicant_full_license1,
	       wpa_supplicant_full_license2,
	       wpa_supplicant_full_license3,
	       wpa_supplicant_full_license4,
	       wpa_supplicant_full_license5);
#endif /* CONFIG_NO_STDOUT_DEBUG */
}


static void wpa_supplicant_fd_workaround(int start)
{
#ifdef __linux__
	static int fd[3] = { -1, -1, -1 };
	int i;
	/* When started from pcmcia-cs scripts, wpa_supplicant might start with
	 * fd 0, 1, and 2 closed. This will cause some issues because many
	 * places in wpa_supplicant are still printing out to stdout. As a
	 * workaround, make sure that fd's 0, 1, and 2 are not used for other
	 * sockets. */
	if (start) {
		for (i = 0; i < 3; i++) {
			fd[i] = open("/dev/null", O_RDWR);
			if (fd[i] > 2) {
				close(fd[i]);
				fd[i] = -1;
				break;
			}
		}
	} else {
		for (i = 0; i < 3; i++) {
			if (fd[i] >= 0) {
				close(fd[i]);
				fd[i] = -1;
			}
		}
	}
#endif /* __linux__ */
}


int main(int argc, char *argv[])
{
	int c, i;
	struct wpa_interface *ifaces, *iface;
	int iface_count, exitcode = -1;
	struct wpa_params params;
	struct wpa_global *global;


// Android平台中，下面这个函数的实现在os_unix.c中。Android对其做了一些修改，主要是权限方面的设置防止某些情况下被破解者利用权限漏洞以获取root权限。
	if (os_program_init())
		return -1;

	os_memset(&params, 0, sizeof(params));
	params.wpa_debug_level = MSG_INFO;

	iface = ifaces = os_zalloc(sizeof(struct wpa_interface));
	if (ifaces == NULL)
		return -1;
	iface_count = 1;

	wpa_supplicant_fd_workaround(1); // 输入输出重定向到/dev/null设备

	for (;;) { // 参数解析，由图4-5所知，Note 2中WPAS启动只使用了4个参数
		c = getopt(argc, argv,
			   "b:Bc:C:D:de:f:g:hi:KLNo:O:p:P:qsTtuvW");
		if (c < 0)
			break;
		switch (c) {
		case 'b':
			iface->bridge_ifname = optarg;
			break;
		case 'B':
			params.daemonize++;
			break;
		case 'c':
		    // 指定配置文件名。注意，该参数赋值给了wpa_interface中的变量
			iface->confname = optarg;
			break;
		case 'C':
			iface->ctrl_interface = optarg;
			break;
		case 'D':
		    // 指定driver名称。注意，该参数赋值给了wpa_interface中的变量
			iface->driver = optarg;
			break;
		case 'd':
#ifdef CONFIG_NO_STDOUT_DEBUG
			printf("Debugging disabled with "
			       "CONFIG_NO_STDOUT_DEBUG=y build time "
			       "option.\n");
			goto out;
#else /* CONFIG_NO_STDOUT_DEBUG */
			params.wpa_debug_level--;
			break;
#endif /* CONFIG_NO_STDOUT_DEBUG */
		case 'e':
			params.entropy_file = optarg;
			break;
#ifdef CONFIG_DEBUG_FILE
		case 'f':
			params.wpa_debug_file_path = optarg;
			break;
#endif /* CONFIG_DEBUG_FILE */
		case 'g':
		    // 指定初始随机数文件，用于后续随机数的生成[^①]
			params.ctrl_interface = optarg;
			break;
		case 'h':
			usage();
			exitcode = 0;
			goto out;
		case 'i':
		    // 指定网络设备接口名，本例是"wlan0"
			iface->ifname = optarg;
			break;
		case 'K':
			params.wpa_debug_show_keys++;
			break;
		case 'L':
			license();
			exitcode = 0;
			goto out;
		case 'o':
			params.override_driver = optarg;
			break;
		case 'O':
			params.override_ctrl_interface = optarg;
			break;
		case 'p':
			iface->driver_param = optarg;
			break;
		case 'P':
			os_free(params.pid_file);
			params.pid_file = os_rel2abs_path(optarg);
			break;
		case 'q':
			params.wpa_debug_level++;
			break;
#ifdef CONFIG_DEBUG_SYSLOG
		case 's':
			params.wpa_debug_syslog++;
			break;
#endif /* CONFIG_DEBUG_SYSLOG */
#ifdef CONFIG_DEBUG_LINUX_TRACING
		case 'T':
			params.wpa_debug_tracing++;
			break;
#endif /* CONFIG_DEBUG_LINUX_TRACING */
		case 't':
			params.wpa_debug_timestamp++;
			break;
#ifdef CONFIG_DBUS
		case 'u':
			params.dbus_ctrl_interface = 1;
			break;
#endif /* CONFIG_DBUS */
		case 'v':
			printf("%s\n", wpa_supplicant_version);
			exitcode = 0;
			goto out;
		case 'W':
			params.wait_for_monitor++;
			break;
		case 'N':
			iface_count++;
			iface = os_realloc_array(ifaces, iface_count,
						 sizeof(struct wpa_interface));
			if (iface == NULL)
				goto out;
			ifaces = iface;
			iface = &ifaces[iface_count - 1]; 
			os_memset(iface, 0, sizeof(*iface));
			break;
		default:
			usage();
			exitcode = 0;
			goto out;
		}
	}

	exitcode = 0;
	// 关键函数①：根据传入的参数，创建并初始化一个wpa_global对象
	global = wpa_supplicant_init(&params);
	if (global == NULL) {
		wpa_printf(MSG_ERROR, "Failed to initialize wpa_supplicant");
		exitcode = -1;
		goto out;
	} else {
		wpa_printf(MSG_INFO, "Successfully initialized "
			   "wpa_supplicant");
	}

	for (i = 0; exitcode == 0 && i < iface_count; i++) {
		if ((ifaces[i].confname == NULL &&
		     ifaces[i].ctrl_interface == NULL) ||
		    ifaces[i].ifname == NULL) {
			if (iface_count == 1 && (params.ctrl_interface ||
						 params.dbus_ctrl_interface))
				break;
			usage();
			exitcode = -1;
			break;
		}
		// 关键函数②：WPAS支持操作多个无线网络设备，此处需将它们一一添加到WPAS中
		// WPAS内部将初始化这些设备
		if (wpa_supplicant_add_iface(global, &ifaces[i]) == NULL)
			exitcode = -1;
	}

    // Android平台中，wpa_supplicant通过select或epoll方式实现多路I/O复用
	if (exitcode == 0)
		exitcode = wpa_supplicant_run(global);

	wpa_supplicant_deinit(global);

out:
	wpa_supplicant_fd_workaround(0);
	os_free(ifaces);
	os_free(params.pid_file);

	os_program_deinit();

	return exitcode;
}
