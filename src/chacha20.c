
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <stdio.h>
#include <stdlib.h>
#include <psa/crypto.h>
#include <psa/crypto_extra.h>
#include <zephyr/logging/log.h>
#include <zephyr/random/rand32.h>
#include "chacha20.h"

#define APP_SUCCESS (0)
#define APP_ERROR (-1)

#define LEN_KEY 0x20
#define LEN_NONCE 0x0C

// static const uint8_t wrongKey_aui8[LEN_KEY]  = {0xd3, 0x64, 0x7a, 0x29, 0xde, 0xd3, 0x15, 0x28,
// 												0xef, 0x56, 0xba, 0xc7, 0x0c, 0x0d, 0x0e, 0x0f,
// 												0x10, 0x11, 0x12, 0x13, 0x14, 0x1a, 0x1b, 0x1c,
// 												0x00, 0x00, 0x00, 0x00, 0x09, 0x12, 0x13, 0x13};
static const uint8_t chachaKey_aui8[LEN_KEY] = {0xe3, 0x64, 0x7a, 0x29, 0xde, 0xd3, 0x15, 0x28,
												0xef, 0x56, 0xba, 0xc7, 0x0c, 0x0d, 0x0e, 0x0f,
												0x10, 0x11, 0x12, 0x13, 0x14, 0x1a, 0x1b, 0x1c,
												0x00, 0x00, 0x00, 0x00, 0x09, 0x12, 0x13, 0x13};
static uint8_t chachaNonce_aui8[LEN_NONCE] = {0x43, 0x82, 0xc3, 0x6b, 0x0a, 0x03, 0x00, 0xCF,
											  0xEA, 0x00, 0x00, 0x00};


static int chacha20Encryption(uint8_t* pDst, uint8_t* pSrc, uint8_t dstLen);

/*
 * srcData: source data to be encrypted.
 * encData: holder to stored encrypted data.
 * len_Dat: length of enc Data.
 */                                           
static int chacha20Encryption(uint8_t *encData, uint8_t *srcData, uint8_t lenEncDataui8)
{
	psa_cipher_operation_t handle = psa_cipher_operation_init();
	psa_cipher_operation_t handle_dec = psa_cipher_operation_init();
	psa_status_t status = PSA_SUCCESS;
	psa_key_handle_t key_handle = 0;
	psa_key_attributes_t key_attributes = psa_key_attributes_init();
	const psa_algorithm_t alg = PSA_ALG_STREAM_CIPHER;
	bool bAbortDecryption = false;

	/* Variables required during multipart update */
	size_t outputLen = 0;
	size_t total_outputLen = 0;
	// int comp_result;
	int ret = APP_ERROR;

	/* Setup the key policy */
	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
	psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_algorithm(&key_attributes, PSA_ALG_STREAM_CIPHER);
	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_CHACHA20);
	psa_set_key_bits(&key_attributes, 256);	// 32 bytes key for chacha

	/* Load the predefined Key */
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

	/* Set initial vector */
	status = psa_cipher_set_iv(&handle, chachaNonce_aui8, sizeof(chachaNonce_aui8));
	if (status != PSA_SUCCESS)
	{
		goto abort;
	}

	/* Encrypt one chunk of information */
	status = psa_cipher_update(&handle, srcData, lenEncDataui8, encData, 
								lenEncDataui8 - total_outputLen, &outputLen);
	if ((status != PSA_SUCCESS) || (outputLen != lenEncDataui8))
	{
		goto abort;
	}

	total_outputLen += outputLen;

	/* Finalise the cipher operation */
	status = psa_cipher_finish(&handle, &encData,
							   lenEncDataui8 - total_outputLen, &outputLen);

	if ((status != PSA_SUCCESS) || (outputLen != 0))
	{
		goto abort;
	}

	/* Add the last output produced, it might be encrypted padding */
	total_outputLen += outputLen;

	ret = APP_SUCCESS;

	/* Go directly to the destroy_key label at this point */
	goto destroy_key;

abort:
	/* Abort the operation */
	status = bAbortDecryption ? psa_cipher_abort(&handle_dec) : psa_cipher_abort(&handle);
	if (status != PSA_SUCCESS)
	{
		ret = APP_ERROR;
	}
destroy_key:
	/* Destroy the key */
	status = psa_destroy_key(key_handle);
	if (status != PSA_SUCCESS)
	{
		ret = APP_ERROR;
	}

	return ret;
}


/*
 *	pSerNo_ui8: serial number, 6 bytes
 *	pEndData_ui8: 6 + 2 + 3 = 11 bytes
 */

/*
 * TxData = Payload + 3 bytes nonce + 4 bytes  CRC
 */
int encryptAdvertising(struct stihlAdvData_st* pDst_st, struct stihlAdvData_st* pSrc_st)
{
    int status = -1;
	
	/* Step 1: Add CRC32 of service data to payload. */
	pSrc_st->plainText_st.crc32_ui32 = crc32_ieee(pSrc_st->plainText_st.servData_aui8, LEN_SERVDATA);
	printk("\ncrc_org: %x", pSrc_st->plainText_st.crc32_ui32 );

	/* Step 2: Create 3 bytes random nonce and add it to nounce. */
	/* sys_rand_get needs crapto engin. */
	sys_rand_get(pSrc_st->randomNonce_aui8, LEN_RANDOM);
	memcpy(pDst_st->randomNonce_aui8, pSrc_st->randomNonce_aui8, LEN_RANDOM);
	memcpy(&chachaNonce_aui8[LEN_NONCE - LEN_RANDOM], pDst_st->randomNonce_aui8, LEN_RANDOM);

	printk("\nrnadom_org: %x, %x, %x", pDst_st->randomNonce_aui8[0], pDst_st->randomNonce_aui8[1], pDst_st->randomNonce_aui8[2]);
	
	/* Step 3: encrypt data */
	status = chacha20Encryption(&(pDst_st->plainText_st), &(pSrc_st->plainText_st), LEN_PAYLOAD);
	return status;
}


/*
 * descrypting advertising
 */
int decryptAdvertising(struct payLoad_st* pDecPayLoad_st, struct stihlAdvData_st* pEncAdvData_st, uint8_t lenPayload_ui8)
{
    int status = -1;
	uint32_t newCrc32_ui32 = 0xFFFFFFFF;

	/* Step 1: Get 3 bytes nonce from encData */
	memcpy(&chachaNonce_aui8[LEN_NONCE - LEN_RANDOM], pEncAdvData_st->randomNonce_aui8, LEN_RANDOM);

	/* Step 2: Decrypt data */	
	status = chacha20Encryption(pDecPayLoad_st, &(pEncAdvData_st->plainText_st), LEN_PAYLOAD);

	/* Step 3: Calculate CRC32 */
	newCrc32_ui32 = crc32_ieee(pDecPayLoad_st->servData_aui8, LEN_SERVDATA);

	if((newCrc32_ui32 == pDecPayLoad_st->crc32_ui32) &&
	   ((uint8_t) LEN_SERVDATA == pDecPayLoad_st->lenSD_ui8 ))
	{
		status = 0;
	}

	return status;
}