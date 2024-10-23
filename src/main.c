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

LOG_MODULE_REGISTER(chacha20, LOG_LEVEL_DBG);

static uint8_t inData[32] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,\
                                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static uint8_t outData[32];
static uint8_t decData[32];
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
uint32_t time_usi64[4]= {0};

int main(void)
{
	uint32_t tDiffEnc_i64 = 0;
	uint32_t tDiffDec_i64 = 0;
	uint32_t ind = 0;
	uint8_t plainText_bo = 0;
	int status;
    
	// uint8_t newSerNr_aui8[LEN_SERIAL_NO] = {0};
	status = crypto_init();
	if (status != APP_SUCCESS)
	{
		return APP_ERROR;
	}
	
	while(1)
	{
        chacha20Encryption(outData, inData, 32);
		LOG_HEXDUMP_INF(inData, LEN_ADVERTISING, "original data");
		LOG_HEXDUMP_INF(outData, LEN_ADVERTISING, "encrypted data");
		k_sleep(K_MSEC(2000));

        chacha20Encryption(decData, outData, 32);
		LOG_HEXDUMP_INF(decData, LEN_ADVERTISING, "decrypted data");
		k_sleep(K_MSEC(2000));
	}

	return APP_SUCCESS;
}
