#ifndef __CHACHA20_H
#define __CHACHA20_H

#define PROTOCOL_ID 0x06
#define MODEL_ID 	0x0005

 
#define LEN_PROTOCOL_ID	0x00
#define LEN_MODEL_ID	0x00
/* not required, but better if length of payload + CRC can be divided by 16. */
#define LEN_LENSD 		1
#define LEN_SERVDATA 	14	//85, 53 or 21
#define LEN_CRC 		2
#define LEN_RANDOM 		3
#define LEN_PAYLOAD     (LEN_LENSD + LEN_SERVDATA + LEN_CRC )
#define LEN_ADVERTISING (LEN_PROTOCOL_ID + LEN_MODEL_ID + LEN_PAYLOAD + LEN_RANDOM)

/* Structure of payload */
struct  __attribute__((packed)) payLoad_st
{
	uint8_t lenSD_ui8;
	uint8_t servData_aui8[LEN_SERVDATA];
	// uint32_t crc32_ui32;
	uint16_t crc16_ui16;
};

/* structrue of advertising */
struct  __attribute__((packed)) stihlAdvData_st
{
	// uint8_t protocolID_ui8;
	// uint16_t modelID_ui16;
	struct payLoad_st plainText_st;
	uint8_t randomNonce_aui8[LEN_RANDOM];
};

extern int encryptAdvertising(struct stihlAdvData_st* pDst_st, struct stihlAdvData_st* pSrc_st);

extern int decryptAdvertising(struct payLoad_st* pDecPayLoad_st, struct stihlAdvData_st* pEncAdvData_st, uint8_t lenPayload_ui8);
extern  int chacha20Encryption(uint8_t* pDst, uint8_t* pSrc, uint8_t dstLen);
#endif