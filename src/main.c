/*
 * Copyright (c) 2019-2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <stdio.h>
#include <stdlib.h>
#include <psa/crypto.h>
#include <psa/crypto_extra.h>
#include <zephyr/logging/log.h>
#include <zephyr/random/rand32.h>
#include "chacha20.h"

#ifdef CONFIG_BUILD_WITH_TFM
#include <tfm_ns_interface.h>
#endif


#define APP_SUCCESS (0)
#define APP_ERROR (-1)

#define PRINT_HEX(p_label, p_text, len)                   \
	({                                                    \
		LOG_HEXDUMP_INF(p_text, len, "Content:");         \
	})

LOG_MODULE_REGISTER(chachapoly, LOG_LEVEL_DBG);

static uint8_t serNr_aui8[LEN_SERIAL_NO] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05 , 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 
 											0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
static uint8_t encData_aui8[LEN_TX_DATA] = {0};
static uint8_t decryptedData_aui8[LEN_ENCRYPTED] = {0};

/* If you want to encrypte data segmentized. */

/* The initial counter of the Chacha20 RFC7539 test vectors is 1, while the PSA
 * APIs assume it to be zero. This means that this expected ciphertext is not
 * the same as the one presented in the RFC
 */
int crypto_init(void)
{
	psa_status_t status;

	/* Initialize PSA Crypto */
	status = psa_crypto_init();
	if (status != PSA_SUCCESS)
		return APP_ERROR;

	return APP_SUCCESS;
}


/* */
int main(void)
{
	int status;
	uint8_t newSerNr_aui8[LEN_SERIAL_NO] = {0};
	status = crypto_init();
	if (status != APP_SUCCESS)
	{
		return APP_ERROR;
	}
	
	while(1)
	{
		status = encrSerialNo_Random(serNr_aui8, LEN_SERIAL_NO, encData_aui8, LEN_TX_DATA);
		if (status != APP_SUCCESS)
		{
			return APP_ERROR;
		}

		status = decrSerialNo_Random(encData_aui8, LEN_TX_DATA, newSerNr_aui8, LEN_SERIAL_NO);
		if (status != APP_SUCCESS)
		{
			return APP_ERROR;
		}

		// LOG_HEXDUMP_INF(p_text, len, "Content:");
		LOG_HEXDUMP_INF(serNr_aui8, LEN_SERIAL_NO, "serial number");
		LOG_HEXDUMP_INF(encData_aui8, LEN_TX_DATA, "Cipher text");
		LOG_HEXDUMP_INF(newSerNr_aui8, sizeof(newSerNr_aui8), "descrypted serial");
		printk("\n");
		k_sleep(K_MSEC(2000));
	}
	// LOG_INF("Chacha example completed successfully.");

	return APP_SUCCESS;
}
