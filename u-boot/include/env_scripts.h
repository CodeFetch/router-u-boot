/*
 * Upgrade and recovery helper environment scripts
 *
 * Copyright (C) 2016 Piotr Dymacz <piotr@dymacz.pl>
 * Copyright (C) 2019 Vincent Wiemann <vw@derowe.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef _ENV_SCRIPTS_H_
#define _ENV_SCRIPTS_H_

/*
 * U-Boot upgrade
 */
#if defined(CONFIG_UPG_SCRIPTS_UBOOT) &&\
    defined(CONFIG_MAX_UBOOT_SIZE_HEX)

	/* Backup size: use image limit size by default */
	#if !defined(CONFIG_UPG_SCRIPTS_UBOOT_SIZE_BCKP_HEX)
		#define CONFIG_UPG_SCRIPTS_UBOOT_SIZE_BCKP_HEX \
				CONFIG_MAX_UBOOT_SIZE_HEX
	#endif

	/* Target address: use CFG_FLASH_BASE by default */
	#if !defined(CONFIG_UPG_SCRIPTS_UBOOT_ADDR_HEX)
		#define CONFIG_UPG_SCRIPTS_UBOOT_ADDR_HEX \
				CFG_FLASH_BASE
	#endif

	/* Limit size: use image limit size by default */
	#if !defined(CONFIG_UPG_SCRIPTS_UBOOT_SIZE_HEX)
		#define CONFIG_UPG_SCRIPTS_UBOOT_SIZE_HEX \
				CONFIG_MAX_UBOOT_SIZE_HEX
	#endif

	/* Small check */
	#if (CONFIG_UPG_SCRIPTS_UBOOT_SIZE_BCKP_HEX < \
	     CONFIG_UPG_SCRIPTS_UBOOT_SIZE_HEX)
		#error "U-Boot backup size must be >= U-Boot image size"
	#endif

	/* Include backup stage only if needed */
	#if (CONFIG_UPG_SCRIPTS_UBOOT_SIZE_BCKP_HEX == \
	     CONFIG_UPG_SCRIPTS_UBOOT_SIZE_HEX)
		#define CONFIG_ENV_UPG_SCRIPTS_UBOOT	\
		"uboot_addr=" MK_STR(CONFIG_UPG_SCRIPTS_UBOOT_ADDR_HEX) "\0" \
		"uboot_size=" MK_STR(CONFIG_UPG_SCRIPTS_UBOOT_SIZE_HEX) "\0" \
		"uboot_upg=" \
			"if ping $serverip; then " \
				"tftpb $loadaddr $uboot_name && " \
				"if itest.l $filesize <= $uboot_size; then " \
					"erase $uboot_addr +$uboot_size && " \
					"cp.b $loadaddr $uboot_addr $uboot_size && " \
					"echo DONE! U-Boot upgraded!; " \
				"else " \
					"echo ERROR! File is too big!; " \
				"fi; " \
			"else " \
				"echo ERROR! $serverip is not reachable!; " \
			"fi\0"
	#else
		#define CONFIG_ENV_UPG_SCRIPTS_UBOOT	\
		"uboot_name=u-boot.bin\0" \
		"uboot_addr=" MK_STR(CONFIG_UPG_SCRIPTS_UBOOT_ADDR_HEX) "\0" \
		"uboot_size=" MK_STR(CONFIG_UPG_SCRIPTS_UBOOT_SIZE_HEX) "\0" \
		"uboot_bckp=" MK_STR(CONFIG_UPG_SCRIPTS_UBOOT_SIZE_BCKP_HEX) "\0" \
		"uboot_upg=" \
			"if ping $serverip; then " \
				"mw.b $loadaddr 0xFF $uboot_bckp && " \
				"cp.b $uboot_addr $loadaddr $uboot_bckp && " \
				"tftpb $loadaddr $uboot_name && " \
				"if itest.l $filesize <= $uboot_size; then " \
					"erase $uboot_addr +$uboot_bckp && " \
					"cp.b $loadaddr $uboot_addr $uboot_bckp && " \
					"echo DONE! U-Boot upgraded!; " \
				"else " \
					"echo ERROR! File is too big!; " \
				"fi; " \
			"else " \
				"echo ERROR! $serverip is not reachable!; " \
			"fi\0"
	#endif

#endif /* CONFIG_UPG_SCRIPTS_UBOOT && CONFIG_MAX_UBOOT_SIZE_HEX */

/*
 * Firmware upgrade
 */
#if defined(CONFIG_UPG_SCRIPTS_FW)

	/* Target address: use CFG_LOAD_ADDR by default */
	#if !defined(CONFIG_UPG_SCRIPTS_FW_ADDR_HEX)
		#define CONFIG_UPG_SCRIPTS_FW_ADDR_HEX	\
				CFG_LOAD_ADDR
	#endif

	#define CONFIG_ENV_UPG_SCRIPTS_FW	\
		"fw_addr=" MK_STR(CONFIG_UPG_SCRIPTS_FW_ADDR_HEX) "\0" \
		"fw_upg=" \
			"if ping $serverip; then " \
				"tftpb $loadaddr $bootfile && " \
				"erase $fw_addr +$filesize && " \
				"cp.b $loadaddr $fw_addr $filesize && " \
				"echo DONE! Firmware upgraded!; " \
			"else " \
				"echo ERROR! $serverip is not reachable!; " \
			"fi\0"

#endif /* CONFIG_UPG_SCRIPTS_FW */

/*
 * Recovery
 */
#if defined(CONFIG_BTN_RECOVERY_SCRIPT) &&\
    defined(CONFIG_GPIO_RESET_BTN)

	#if !defined(CONFIG_CMD_BUTTON) ||\
	    !defined(CONFIG_CMD_SLEEP)  ||\
	    !defined(CONFIG_CMD_LED)    ||\
	    !defined(CONFIG_CMD_ITEST)  ||\
	    !defined(CONFIG_CMD_SETEXPR)
		#error "Commands setexpr, itest, sleep, button and led{on, off} are required for recovery"
	#endif

	/*
	 * Blink as a special signal
	 */
	#define SCRIPT_BLINK \
		"ledon;" \
		"sleep 250;" \
		"ledoff;" \
		"sleep 250;" \
		"ledon;" \
		"sleep 250;" \
		"ledoff;" \
		"sleep 250;" \
		"ledon;"


	/*
	 * DHCP client
	 */
	#if defined(CONFIG_CMD_DHCP)
		#define SCRIPT_DHCP \
			"echo Trying to acquire a DHCP lease...;" \
			"dhcp;" \
			SCRIPT_BLINK
	#else
		#define SCRIPT_DHCP	""
	#endif

	/*
	 * TFTP recovery
	 */
	#if defined(CONFIG_CMD_DHCP)
		#define SCRIPT_TFTP_PART_1_DHCP \
			"echo - 5s for TFTP firmware recovery using DHCP;" 
		#define SCRIPT_TFTP_PART_2_DHCP \
			"elif itest $cnt >= 0x5; then " \
				"echo Starting TFTP firmware recovery using DHCP...;" \
				"echo;" \
				SCRIPT_DHCP \
				"run fw_upg;"
	#else
		#define SCRIPT_TFTP_PART_1_DHCP ""
		#define SCRIPT_TFTP_PART_2_DHCP ""
	#endif

	#define SCRIPT_TFTP_PART_1 \
			"echo - 3s for TFTP firmware recovery using static IPs;" \
			SCRIPT_TFTP_PART_1_DHCP

	#define SCRIPT_TFTP_PART_2 \
				SCRIPT_TFTP_PART_2_DHCP \
				"elif itest $cnt >= 0x3; then " \
					"echo Starting TFTP firmware recovery using static IPs...;" \
					"setenv tmp_ipaddr $ipaddr;" \
					"setenv tmp_serverip $serverip;" \
					"setenv ipaddr $tftp_ipaddr;" \
					"setenv serverip $tftp_serverip;" \
					"echo;" \
					"run fw_upg;" \
					"setenv ipaddr $tmp_ipaddr;" \
					"setenv serverip $tmp_serverip;" \
					"setenv tmp_ipaddr;" \
					"setenv tmp_serverip;"

	/*
	 * Web recovery
	 */
 	#if defined(CONFIG_CMD_HTTPD)
		#define SCRIPT_HTTP_PART_1_STATIC	"echo - 9s for Web recovery with static IP address;"
		#define SCRIPT_HTTP_PART_2_STATIC \
			"elif itest $cnt >= 9; then " \
				"echo Starting webserver for firmware recovery...;" \
				"setenv stop_boot 1;" \
				"setenv tmp_ipaddr $ipaddr;" \
				"setenv ipaddr $web_ipaddr;" \
				"echo;" \
				"httpd;" \
				"setenv ipaddr $tmp_ipaddr;" \
				"setenv tmp_ipaddr;"

		#if defined(CONFIG_CMD_DHCP)
			#define SCRIPT_HTTP_PART_1 \
				"echo - 7s for Web recovery as DHCP client;" \
				SCRIPT_HTTP_PART_1_STATIC

			#define SCRIPT_HTTP_PART_2 \
				SCRIPT_HTTP_PART_2_STATIC \
				"elif itest $cnt >= 7; then " \
					SCRIPT_DHCP \
					"echo Starting webserver for firmware recovery using DHCP...;" \
					"setenv stop_boot 1;" \
					"echo;" \
					"httpd;"
		#else
			#define SCRIPT_HTTP_PART_1	SCRIPT_HTTP_PART_1_STATIC
			#define SCRIPT_HTTP_PART_2	SCRIPT_HTTP_PART_2_STATIC
		#endif
	#else
		#define SCRIPT_HTTP_PART_1	""
		#define SCRIPT_HTTP_PART_2	\
		"elif itest $cnt < 5; then "
	#endif

	/*
	 * Final recovery script
	 */
	#define CONFIG_ENV_BTN_RECOVERY_SCRIPT	\
		"recovery=" \
		"if button; then " \
			"sleep 600;" \
			"setenv cnt 0;" \
			"setenv stop_boot;" \
			"echo Keep the button pressed for at least:;" \
			SCRIPT_TFTP_PART_1 \
			SCRIPT_HTTP_PART_1 \
			"echo - 12s for network console;" \
			"echo;" \
			"while button && itest $cnt < 0xE; do " \
				"ledon;" \
				"sleep 300;" \
				"echo . \'\\\\c\';" \
				"sleep 300;" \
				"ledoff;" \
				"sleep 600;" \
				"setexpr cnt $cnt + 1;" \
			"done;" \
			"echo;" \
			"if itest $cnt >= 0xE; then " \
				"echo \\#\\# Error: 14s limit reached.;" \
				"echo Continuing normal boot...;" \
				SCRIPT_BLINK \
				"echo;" \
			"elif itest $cnt >= 12; then " \
				"echo Starting network console...;" \
				"setenv stop_boot 1;" \
				"echo;" \
				"startnc;" \
			SCRIPT_HTTP_PART_2 \
			SCRIPT_TFTP_PART_2 \
			"elif itest $cnt < 3; then " \
				"echo \\#\\# Error: the button was not pressed long enough!;" \
				"echo Continuing normal boot...;" \
				SCRIPT_BLINK \
				"echo;" \
			"fi;" \
			"setenv cnt;" \
		"fi\0"

#endif /* CONFIG_BTN_RECOVERY_SCRIPT && CONFIG_GPIO_RESET_BTN */

#endif /* _ENV_SCRIPTS_H_ */
