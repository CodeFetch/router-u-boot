/*
 * Common functions for QC/A WiSoCs based boards support
 *
 * Copyright (C) 2016 Piotr Dymacz <piotr@dymacz.pl>
 *
 * Partially based on:
 * Linux/arch/mips/ath79/setup.c
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include <config.h>
#include <common.h>
#include <flash.h>
#include <asm/mipsregs.h>
#include <asm/addrspace.h>
#include <soc/qca_soc_common.h>

#define ALIGN_SIZE	"8"

DECLARE_GLOBAL_DATA_PTR;

static u32 mac_is_not_valid = 0;

/*
 * Put QCA SOC name, version and revision in buffer
 */
void qca_soc_name_rev(char *buf)
{
	u32 id, major, rev;
	const char *name = NULL;

	if (buf == NULL)
		return;

	/* Get revision ID value */
	id = qca_soc_reg_read(QCA_RST_REVISION_ID_REG);

	major = id & QCA_RST_REVISION_ID_MAJOR_MASK;
	rev = id & QCA_RST_REVISION_ID_REV_MASK;

	switch (major) {
#if (SOC_TYPE & 0)
	case QCA_RST_REVISION_ID_MAJOR_AR71XX_VAL: name="AR71xx"; break;
	case QCA_RST_REVISION_ID_MAJOR_AR913X_VAL: name="AR913x"; break;
	case QCA_RST_REVISION_ID_MAJOR_AR7240_VAL: name="AR7240"; break;
	case QCA_RST_REVISION_ID_MAJOR_AR7241_VAL: name="AR7241"; break;
	case QCA_RST_REVISION_ID_MAJOR_AR7242_VAL: name="AR7242"; break;
	case QCA_RST_REVISION_ID_MAJOR_TP9343_VAL: name="TP9343"; break;
#elif (SOC_TYPE & QCA_AR933X_SOC)
	case QCA_RST_REVISION_ID_MAJOR_AR9330_VAL: name="AR9330"; break;
	case QCA_RST_REVISION_ID_MAJOR_AR9331_VAL: name="AR9331"; break;
#elif (SOC_TYPE & QCA_AR934X_SOC)
	case QCA_RST_REVISION_ID_MAJOR_AR9341_VAL: name="AR9341"; break;
	case QCA_RST_REVISION_ID_MAJOR_AR9342_VAL: name="AR9342"; break;
	case QCA_RST_REVISION_ID_MAJOR_AR9344_VAL: name="AR9344"; break;
#elif (SOC_TYPE & QCA_QCA953X_SOC)
	case QCA_RST_REVISION_ID_MAJOR_QCA9533_VAL:    name="QCA953x ver. 1"; break;
	case QCA_RST_REVISION_ID_MAJOR_QCA9533_V2_VAL: name="QCA953x ver. 2"; break;
#elif (SOC_TYPE & QCA_QCA955X_SOC)
	case QCA_RST_REVISION_ID_MAJOR_QCA9556_VAL: name="QCA9556"; break;
	case QCA_RST_REVISION_ID_MAJOR_QCA9558_VAL: name="QCA9558"; break;
#elif (SOC_TYPE & QCA_QCA956X_SOC)
	case QCA_RST_REVISION_ID_MAJOR_QCA956X_VAL: name="QCA956x"; break;
#endif
       }

	if (name) {
		sprintf(buf, "%s rev. %d", name, rev);
	} else {
		sprintf(buf, "Unknown (%04x)", major | rev);
	}
}

/*
 * Returns last reset reason:
 * 1 -> reset by watchdog
 * 0 -> normal reset
 */
int last_reset_wdt()
{
	u32 reg;

	reg = qca_soc_reg_read(QCA_RST_WATCHDOG_TIMER_CTRL_REG);
	if (reg & QCA_RST_WATCHDOG_TIMER_CTRL_LAST_MASK)
		return 1;

	return 0;
}

/*
 * Prints available information about the board
 */
void print_board_info(void)
{
	u32 ahb_clk, cpu_clk, ddr_clk, spi_clk, ref_clk;
#if defined(CONFIG_PCI)
	u32 did, vid;
#endif
	u32 bank;
	bd_t *bd = gd->bd;
	char buffer[24];

	/* Show warning if last reboot was caused by SOC watchdog */
	if (last_reset_wdt())
		printf_wrn("reset caused by watchdog!\n\n");

	/* Board name */
	printf("%" ALIGN_SIZE "s %s\n",
	       "BOARD:", MK_STR(CONFIG_BOARD_CUSTOM_STRING));

	/* SOC name, version and revision */
	qca_soc_name_rev(buffer);
	printf("%" ALIGN_SIZE "s %s\n", "SOC:", buffer);

	/* MIPS CPU type */
	cpu_name(buffer);
	printf("%" ALIGN_SIZE "s %s\n", "CPU:", buffer);

	/* RAM size and type */
	printf("%" ALIGN_SIZE "s ", "RAM:");
	print_size(bd->bi_memsize, "");

	switch (qca_dram_type()) {
	case RAM_MEMORY_TYPE_SDR:
		puts(" SDR ");
		break;
	case RAM_MEMORY_TYPE_DDR1:
		puts(" DDR1 ");
		break;
	case RAM_MEMORY_TYPE_DDR2:
		puts(" DDR2 ");
		break;
	default:
		break;
	}

	/* DDR interface width */
	printf("%d-bit ", qca_dram_ddr_width());

	/* tCL-tRCD-tRP-tRAS latency */
	printf("CL%d-%d-%d-%d\n", qca_dram_cas_lat(),
				  qca_dram_trcd_lat(),
				  qca_dram_trp_lat(),
				  qca_dram_tras_lat());

	/* SPI NOR FLASH sizes and types */
	printf("%" ALIGN_SIZE "s ", "FLASH:");

	for (bank = 0; bank < CFG_MAX_FLASH_BANKS; bank++) {
		if (flash_info[bank].size == 0)
			continue;

		if (bank > 0)
			printf("%" ALIGN_SIZE "s ", " ");

		print_size(flash_info[bank].size, "");

		if (flash_info[bank].manuf_name != NULL)
			printf(" %s", flash_info[bank].manuf_name);

		if (flash_info[bank].model_name != NULL)
			printf(" %s", flash_info[bank].model_name);

		puts("\n");
	}

	/* PCIE device/s info */
#if defined(CONFIG_PCI)
	printf("%" ALIGN_SIZE "s ", "PCIe:");

	#if (SOC_TYPE & QCA_AR934X_SOC) |\
		(SOC_TYPE & QCA_QCA955X_SOC)
	if (!qca_pcie0_in_ep_mode()) {
		if (qca_pcie_dev_info(0, &vid, &did))
			puts(qca_pcie_dev_name(vid, did));
		else
			puts("no device");
	} else {
		puts("EP mode");
	}
	#elif (SOC_TYPE & QCA_QCA953X_SOC)
	if (qca_pcie_dev_info(0, &vid, &did))
		puts(qca_pcie_dev_name(vid, did));
	else
		puts("no device");
	#endif

	#if (SOC_TYPE & QCA_QCA956X_SOC)
	if (qca_pcie_dev_info(1, &vid, &did))
		puts(qca_pcie_dev_name(vid, did));
	else
		puts("no device");
	#elif (SOC_TYPE & QCA_QCA955X_SOC)
	puts(", ");
	if (qca_pcie_dev_info(1, &vid, &did))
		puts(qca_pcie_dev_name(vid, did));
	else
		puts("no device");
	#endif

	putc('\n');
#endif

	/* MAC address */
	printf("%" ALIGN_SIZE "s %02X:%02X:%02X:%02X:%02X:%02X", "MAC:",
		bd->bi_enetaddr[0],bd->bi_enetaddr[1], bd->bi_enetaddr[2],
		bd->bi_enetaddr[3], bd->bi_enetaddr[4], bd->bi_enetaddr[5]);

	if (mac_is_not_valid)
		puts(" (fixed)\n");
	else
		puts("\n");

	/* UART real baudrate */
	printf("%" ALIGN_SIZE "s %u bps\n", "UART:", gd->baudrate);

	/* System clocks */
	printf("%" ALIGN_SIZE "s CPU/RAM/AHB/SPI/REF\n", "CLOCKS:");

	qca_sys_clocks(&cpu_clk, &ddr_clk, &ahb_clk, &spi_clk, &ref_clk);
	cpu_clk = cpu_clk / 1000000;
	ddr_clk = ddr_clk / 1000000;
	ahb_clk = ahb_clk / 1000000;
	spi_clk = spi_clk / 1000000;
	ref_clk = ref_clk / 1000000;

	printf("%" ALIGN_SIZE "s %3d/%3d/%3d/%3d/%3d MHz\n",
		" ", cpu_clk, ddr_clk, ahb_clk, spi_clk, ref_clk);

	puts("\n");
}

/*
 * Reads MAC address if available or uses fixed one
 */
void macaddr_init(u8 *mac_addr)
{
	u8 buffer[6];
	u8 fixed_mac[6] = {0x00, 0x03, 0x7F, 0x09, 0x0B, 0xAD};

#if defined(OFFSET_MAC_ADDRESS)
	memcpy(buffer, (void *)(CFG_FLASH_BASE
		+ OFFSET_MAC_DATA_BLOCK + OFFSET_MAC_ADDRESS), 6);

	/*
	 * Check first LSBit (I/G bit) and second LSBit (U/L bit) in MSByte of vendor part
	 * both of them should be 0:
	 * I/G bit == 0 -> Individual MAC address (unicast address)
	 * U/L bit == 0 -> Burned-In-Address (BIA) MAC address
	 */
	if (CHECK_BIT((buffer[0] & 0xFF), 0) != 0 ||
	    CHECK_BIT((buffer[0] & 0xFF), 1) != 0) {
		memcpy(buffer, fixed_mac, 6);
		mac_is_not_valid = 1;
	}
#else
	memcpy(buffer, fixed_mac, 6);
	mac_is_not_valid = 1;
#endif

	memcpy(mac_addr, buffer, 6);
}

/*
 * Returns "reset button" status:
 * 1 -> button is pressed
 * 0 -> button is not pressed
 */
int reset_button_status(void)
{
#if defined(CONFIG_GPIO_RESET_BTN)
	u32 gpio;

	gpio = qca_soc_reg_read(QCA_GPIO_IN_REG);

	if (gpio & (1UL << CONFIG_GPIO_RESET_BTN)) {
	#if defined(CONFIG_GPIO_RESET_BTN_ACTIVE_LOW)
		return 0;
	#else
		return 1;
	#endif
	} else {
	#if defined(CONFIG_GPIO_RESET_BTN_ACTIVE_LOW)
		return 1;
	#else
		return 0;
	#endif
	}
#else
	return 0;
#endif
}

/*
 * Returns main CPU clock in Hz
 */
u32 main_cpu_clk(void)
{
	u32 cpu_clk;

	qca_sys_clocks(&cpu_clk, NULL, NULL, NULL, NULL);

	return cpu_clk;
}

/*
 * Calls full chip reset
 */
void full_reset(void)
{
	qca_full_chip_reset();
}
