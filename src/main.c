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

// static uint8_t exservData_aui8[LEN_SERVDATA] = {1,2,3,4,5,6,7,8,9,0, \
// 												1,2,3,4,5,6,7,8,9,0, \
// 												1,2,3,4,5,6,7,8,9,0, \
// 												1,2,3,4,5,6,7,8,9,0, \
// 												1,2,3};
static uint8_t exservData_aui8[LEN_SERVDATA] = {65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65};
static struct stihlAdvData_st inputData_st = { .plainText_st.lenSD_ui8 = LEN_SERVDATA, .plainText_st.crc16_ui16 = 0xFFFF, .randomNonce_aui8 = {0}};

static struct stihlAdvData_st outputData_st = { .plainText_st.lenSD_ui8 = LEN_SERVDATA,.plainText_st.crc16_ui16 = 0xFFFF, .randomNonce_aui8 = {0}};

static struct stihlAdvData_st decData_st;

// static uint8_t encData_aui8[LEN_TX_DATA] = {0};
// static uint8_t decryptedData_aui8[LEN_ENCRYPTED] = {0};

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
uint32_t time_usi64[4]= {0};

int main(void)
{
	uint32_t tDiffEnc_i64 = 0;
	uint32_t tDiffDec_i64 = 0;
	uint32_t ind = 0;
	uint8_t plainText_bo = 0;
	int status;
	memcpy(inputData_st.plainText_st.servData_aui8, exservData_aui8, LEN_SERVDATA);
	// uint8_t newSerNr_aui8[LEN_SERIAL_NO] = {0};
	status = crypto_init();
	if (status != APP_SUCCESS)
	{
		return APP_ERROR;
	}
	
	while(1)
	{
		ind = 0;

		// time_usi64[0] = k_uptime_get_32();

		while(ind < 1)
		{
			status = encryptAdvertising(&outputData_st, &inputData_st);
			if (status != APP_SUCCESS)
			{
				printk("error \n");
				return APP_ERROR;
			}
			ind++;
		}
		// time_usi64[1] = k_uptime_get_32();

		ind = 0;
		// time_usi64[2] = k_uptime_get_32();
			// while(ind < 1)
			// {
			// 	status = decryptAdvertising(&(decData_st.plainText_st), &(outputData_st), LEN_PAYLOAD);
			// 	if (status != APP_SUCCESS)
			// 	{
			// 		printk("error \n");
			// 		return APP_ERROR;
			// 	}
			// 	ind++;
			// }
			// time_usi64[3] = k_uptime_get_32();

		// tDiffEnc_i64 = time_usi64[1] - time_usi64[0];
		// tDiffDec_i64 = time_usi64[3] - time_usi64[2];
		
		// printk("\n in protocol : %x", inputData_st.protocolID_ui8);
		// printk("\n in prod : %x", inputData_st.modelID_ui16);
		if(plainText_bo == 0)
		{
			LOG_HEXDUMP_INF(&(inputData_st), LEN_PAYLOAD, "payload(15 bytes) + CRC(2 bytes)");
			plainText_bo++;
		}
		// printk("\n in crc : %x", inputData_st.plainText_st.crc32_ui32);

		// LOG_HEXDUMP_INF(inputData_st.randomNonce_aui8, LEN_RANDOM, "random (4bytes)");
		
		// printk("\n out protocol : %x", outputData_st.protocolID_ui8);
		printk("\n"); //out prod : %x", outputData_st.modelID_ui16);
		LOG_HEXDUMP_INF(&(outputData_st), LEN_ADVERTISING, "encrypted data(17 bytes) + random(4 bytes)");
		// printk("\n out crc : %x", outputData_st.plainText_st.crc32_ui32);

		// LOG_HEXDUMP_INF(outputData_st.randomNonce_aui8, LEN_RANDOM, "out random");


		// printk("------------------------------------------");
	// LOG_INF("Chacha example completed successfully.");

		k_sleep(K_MSEC(5000));
	}

	return APP_SUCCESS;
}
