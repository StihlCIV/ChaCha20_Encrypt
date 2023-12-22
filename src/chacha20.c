
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

static const uint8_t wrongKey_aui8[LEN_KEY]  = {0xd3, 0x64, 0x7a, 0x29, 0xde, 0xd3, 0x15, 0x28,
												0xef, 0x56, 0xba, 0xc7, 0x0c, 0x0d, 0x0e, 0x0f,
												0x10, 0x11, 0x12, 0x13, 0x14, 0x1a, 0x1b, 0x1c,
												0x00, 0x00, 0x00, 0x00, 0x09, 0x12, 0x13, 0x13};
static const uint8_t chachaKey_aui8[LEN_KEY] = {0xe3, 0x64, 0x7a, 0x29, 0xde, 0xd3, 0x15, 0x28,
												0xef, 0x56, 0xba, 0xc7, 0x0c, 0x0d, 0x0e, 0x0f,
												0x10, 0x11, 0x12, 0x13, 0x14, 0x1a, 0x1b, 0x1c,
												0x00, 0x00, 0x00, 0x00, 0x09, 0x12, 0x13, 0x13};
static uint8_t chachaNonce_aui8[LEN_NONCE] = {0x43, 0x82, 0xc3, 0x6b, 0x0a, 0x03, 0x00, 0xCF,
											  0xEA, 0x00, 0x00, 0x00};


static int chacha20Encryption(uint8_t *, uint8_t *, uint8_t, uint8_t );

/**/                                           
static int chacha20Encryption(uint8_t *srcData, uint8_t *encData, uint8_t len_ui8, uint8_t keyNo_ui8)
{
	psa_cipher_operation_t handle = psa_cipher_operation_init();
	psa_cipher_operation_t handle_dec = psa_cipher_operation_init();
	psa_status_t status = PSA_SUCCESS;
	psa_key_handle_t key_handle = 0;
	psa_key_attributes_t key_attributes = psa_key_attributes_init();
	const psa_algorithm_t alg = PSA_ALG_STREAM_CIPHER;
	bool bAbortDecryption = false;

	/* Variables required during multipart update */
	// size_t data_left = LEN_ENCRYPTED;
	// size_t start_idx = 0;
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
	if(keyNo_ui8 > 1)
	{
		status = psa_import_key(&key_attributes, wrongKey_aui8, sizeof(wrongKey_aui8), &key_handle);
	}
	else
	{
		status = psa_import_key(&key_attributes, chachaKey_aui8, sizeof(chachaKey_aui8), &key_handle);
	}
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

	/* Encrypt one chunk of information */
	status = psa_cipher_update(&handle, srcData, len_ui8, encData, 
								len_ui8 - total_outputLen, &outputLen);
	if (status != PSA_SUCCESS)
	{
		goto abort;
	}

	if (outputLen != len_ui8)
	{
		goto abort;
	}

	total_outputLen += outputLen;

	/* Finalise the cipher operation */
	status = psa_cipher_finish(&handle, &encData,
							   len_ui8 - total_outputLen, &outputLen);

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
int encrSerialNo_Random(uint8_t* pSerNo_ui8, uint8_t sizeSer_ui8, uint8_t* pEncData_ui8, uint8_t sizeEncData_ui8)
{
	uint16_t seed_ui16 = 0x1234;
	uint16_t crcSer_ui16 = 0xFFFF;
    uint8_t lenEncData_ui8 = sizeSer_ui8 + LEN_CRC16;
    uint8_t lenTxData_ui8 = lenEncData_ui8 + LEN_RANDOM;
	uint8_t plainData_aui8[lenEncData_ui8];
	uint8_t randNonce_aui8[LEN_RANDOM];
    int status = -1;
	sys_rand_get(randNonce_aui8, sizeof(randNonce_aui8));

    /* compute CRC16 */
    crcSer_ui16 = crc16_itu_t(seed_ui16, pSerNo_ui8, sizeSer_ui8);
    memcpy(plainData_aui8, pSerNo_ui8, sizeSer_ui8);
    plainData_aui8[sizeSer_ui8] = (uint8_t)(crcSer_ui16 >> 8);
    plainData_aui8[sizeSer_ui8+1] = (uint8_t)(crcSer_ui16);

    /* create 3 random for Nonce. */
    sys_rand_get(randNonce_aui8, LEN_RANDOM);
    memcpy(&chachaNonce_aui8[lenEncData_ui8], randNonce_aui8, LEN_RANDOM);

    /* encrypt data */
    status = chacha20Encryption(plainData_aui8, pEncData_ui8, lenEncData_ui8, 0);
    if(sizeEncData_ui8 >= (lenTxData_ui8))
    {
        memcpy(&pEncData_ui8[lenEncData_ui8], randNonce_aui8, LEN_RANDOM);
    }
	
	return status;
}

int decrSerialNo_Random(uint8_t* rxData_aui8, uint8_t sizeRxD_ui8, uint8_t* newSerNr_aui8, uint8_t sizeSer_ui8)
{
    int status = -1;
	uint16_t seed_ui16 = 0x1234;
	uint16_t newCrc16_ui16 = 0x0000;
	uint16_t crcSer_ui16 = 0xFFFF;
    uint8_t lenEncData_ui8 = LEN_SERIAL_NO + LEN_CRC16;   // 8bytes
    uint8_t lenTxData_ui8 = lenEncData_ui8 + LEN_RANDOM;
	uint8_t decData_aui8[lenEncData_ui8];
	uint8_t randNonce_aui8[LEN_RANDOM];

    if(sizeRxD_ui8 >= lenTxData_ui8)   // 11 bytes at least.
    {
        /* get 3 bytes nonce from encData */
        // memcpy(randNonce_aui8, &rxData_aui8[lenEncData_ui8], LEN_RANDOM);
        /* encrypt data */
        status = chacha20Encryption(rxData_aui8, decData_aui8, lenEncData_ui8, 0);
        
        memcpy(&crcSer_ui16, &decData_aui8[LEN_SERIAL_NO], LEN_CRC16);         
        crcSer_ui16 = (uint16_t)(decData_aui8[LEN_SERIAL_NO] << 8);         
        crcSer_ui16 += (uint16_t)(decData_aui8[LEN_SERIAL_NO+1]);
        newCrc16_ui16 = crc16_itu_t(seed_ui16, decData_aui8, LEN_SERIAL_NO);

        if(newCrc16_ui16 == crcSer_ui16)
        {
            memcpy(newSerNr_aui8, decData_aui8, LEN_SERIAL_NO);
            status = 0;
        }
    }
	return status;
}