/*
 * Copyright (C) 2016 Piotr Dymacz <piotr@dymacz.pl>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include <config.h>
#include <common.h>
#include <asm/addrspace.h>
#include <soc/qca_soc_common.h>

/*
 * DRAM init
 */
long int dram_init()
{
#ifndef CONFIG_SKIP_LOWLEVEL_INIT
	qca_dram_init();
#endif

	/* Take WMAC out of reset */
	qca_soc_reg_read_clear(QCA_RST_RESET_REG, QCA_RST_RESET_RTC_RST_MASK);

	return (long int)qca_dram_size();
}
