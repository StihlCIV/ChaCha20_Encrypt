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

#ifdef CONFIG_BUILD_WITH_TFM
#include <tfm_ns_interface.h>
#endif

#define PROTOCOL_ID		0x16
#define PRODUCT_ID		0x05

#define LEN_SERIAL_NO	0x06
#define LEN_CRC16		0x02
#define LEN_ENCRYPTED	(LEN_SERIAL_NO + LEN_CRC16)
#define LEN_RANDOM		0x03
#define LEN_TX_DATA		(LEN_ENCRYPTED + LEN_RANDOM)
#define LEN_KEY			0x20
#define LEN_NONCE		0x0C

#define APP_SUCCESS (0)
#define APP_ERROR 	(-1)
#define APP_ERROR_MESSAGE "Example exited with error!"

#define PRINT_HEX(p_label, p_text, len)                           \
	({                                                        \
		LOG_INF("---- %s (len: %u): ----", p_label, len); \
		LOG_HEXDUMP_INF(p_text, len, "Content:");         \
		LOG_INF("---- %s end  ----", p_label);            \
	})

LOG_MODULE_REGISTER(chachapoly, LOG_LEVEL_DBG);

static uint8_t serialNumber_aui8[LEN_SERIAL_NO]		= {1,2,3,4,5,6};
static uint8_t plainText_aui8[LEN_ENCRYPTED] 		= {1,2,3,4,5,6,7,8,9};
static uint8_t encryptedData_aui8[LEN_ENCRYPTED] 	= {0};
static uint8_t decryptedData_aui8[LEN_ENCRYPTED] 	= {0};

static const uint8_t chachaKey_aui8[LEN_KEY] 		= { 0xe3, 0x64, 0x7a, 0x29, 0xde, 0xd3, 0x15, 0x28, 
														0xef, 0x56, 0xba, 0xc7, 0x0c, 0x0d, 0x0e, 0x0f, 
														0x10, 0x11, 0x12, 0x13, 0x14, 0x1a, 0x1b, 0x1c,
														0x00, 0x00, 0x00, 0x00, 0x09, 0x12, 0x13, 0x13 };
static uint8_t chachaNonce_aui8[LEN_NONCE] 			= { 0x43, 0x82, 0xc3, 0x6b, 0x0a, 0x03, 0x00, 0xCF,
														0xEA, 0x00, 0x00, 0x00 };
static uint16_t crc16_ui16 = 0xFFFF;	
/* If you want to encrypte data segmentized. */
static size_t lengths[1] 							= {LEN_ENCRYPTED};													

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


int chacha20Encryption(uint8_t* srcData, uint8_t* encData)
{
	psa_cipher_operation_t handle = psa_cipher_operation_init();
	psa_cipher_operation_t handle_dec = psa_cipher_operation_init();
	psa_status_t status = PSA_SUCCESS;
	psa_key_handle_t key_handle = 0;
	psa_key_attributes_t key_attributes = psa_key_attributes_init();
	const psa_algorithm_t alg = PSA_ALG_STREAM_CIPHER;
	bool bAbortDecryption = false;

	/* Variables required during multipart update */
	size_t data_left = LEN_ENCRYPTED;
	size_t start_idx = 0;
	size_t outputLen = 0;
	size_t total_outputLen = 0;
	int comp_result;
	int ret = APP_ERROR;

	/* Setup the key policy */
	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
	psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_algorithm(&key_attributes, PSA_ALG_STREAM_CIPHER);
	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_CHACHA20);
	psa_set_key_bits(&key_attributes, 256);

	/* Set the Key */
    status = psa_import_key(&key_attributes, chachaKey_aui8, sizeof(chachaKey_aui8), &key_handle);
	if (status != PSA_SUCCESS)
	{
		return APP_ERROR;
	}

	/* Setup algorithm  */
	status = psa_cipher_encrypt_setup(&handle, key_handle, alg);
	if (status != PSA_SUCCESS)
	{
		goto destroy_key;
	}

	/* Set NonceV */
	status = psa_cipher_set_iv(&handle, chachaNonce_aui8, sizeof(chachaNonce_aui8));
	if (status != PSA_SUCCESS)
	{
		goto abort;
	}

	for (int i = 0; i < sizeof(lengths) / sizeof(size_t); i++)
	{
		/* Encrypt one chunk of information */
		status = psa_cipher_update(&handle, srcData, lengths[i],
		    encData, LEN_ENCRYPTED - total_outputLen,
		    &outputLen);

		if (status != PSA_SUCCESS)
		{
			goto abort;
		}

		if (outputLen != lengths[i])
		{
			goto abort;
		}

		data_left -= lengths[i];
		total_outputLen += outputLen;
		start_idx += lengths[i];
	}

	/* Finalise the cipher operation */
	status = psa_cipher_finish(&handle, &encData,
	    LEN_ENCRYPTED - total_outputLen, &outputLen);

	if (status != PSA_SUCCESS)
	{
		goto abort;
	}

	if (outputLen != 0)
	{
		goto abort;
	}

	/* Add the last output produced, it might be encrypted padding */
	total_outputLen += outputLen;

	/* Setup the decryption object */
	status = psa_cipher_decrypt_setup(&handle_dec, key_handle, alg);
	if (status != PSA_SUCCESS)
	{
		goto destroy_key;
	}
	
	ret = APP_SUCCESS;

	/* Go directly to the destroy_key label at this point */
	goto destroy_key;

abort:
	/* Abort the operation */
	status = bAbortDecryption ? psa_cipher_abort(&handle_dec) : psa_cipher_abort(&handle);
	if (status != PSA_SUCCESS)
	{
		LOG_INF("Error aborting the operation");
	}
destroy_key:
	/* Destroy the key */
	status = psa_destroy_key(key_handle);
	if (status != PSA_SUCCESS)
	{
		LOG_INF("Error destroying a key");
	}

	return ret;
}


/* */
int main(void)
{
	int status;

	status = crypto_init();
	if (status != APP_SUCCESS)
	{
		return APP_ERROR;
	}

	status = chacha20Encryption(plainText_aui8, encryptedData_aui8);
	status = chacha20Encryption(encryptedData_aui8, decryptedData_aui8);
	if (status != APP_SUCCESS)
	{
		return APP_ERROR;
	}

	// LOG_HEXDUMP_INF(p_text, len, "Content:");
	LOG_HEXDUMP_INF(plainText_aui8, sizeof(plainText_aui8), "Plain text");
	LOG_HEXDUMP_INF(encryptedData_aui8, sizeof(encryptedData_aui8), "Cipher text");
	LOG_HEXDUMP_INF(decryptedData_aui8, sizeof(decryptedData_aui8), "Decrypted text");

	// LOG_INF("Chacha example completed successfully.");

	return APP_SUCCESS;
}
