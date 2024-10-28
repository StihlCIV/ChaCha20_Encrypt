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

static uint8_t inData[55] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9,\
                             10, 11, 12, 13, 14, 15, 16, 17, 18, 19,\
                             20, 21, 22, 23, 24, 25, 26, 27, 28, 29,\
                             30, 31, 32, 33, 34, 35, 36, 37, 38, 39,\
                             40, 41, 42, 43, 44, 45, 46, 47, 48, 49,\
                             50, 51, 52, 53, 54};
static uint8_t outData[55];
static uint8_t decData[55];
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
        chacha20Encryption(outData, inData, 55);
		LOG_HEXDUMP_INF(inData, 42, "original data");
		LOG_HEXDUMP_INF(outData, 42, "encrypted data");
		k_sleep(K_MSEC(2000));

        chacha20Encryption(decData, outData, 42);
		LOG_HEXDUMP_INF(decData, 42, "decrypted data");
		k_sleep(K_MSEC(5000));
	}

	return APP_SUCCESS;
}
