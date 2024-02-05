#ifndef __CHACHA20_H
#define __CHACHA20_H
#define PROTOCOL_ID 0x16
#define PRODUCT_ID 0x05

 
#define LEN_PROTOCOL_ID	0x01
#define LEN_PRODUCT_ID	0x02
/* not required, but better if length of payload + CRC can be divided by 16. */
#define LEN_PAYLOAD 	0x5C	//92
#ifdef CHECK_16 
    #define LEN_CRC 	0x02
#else
    #define LEN_CRC 	0x04
#endif
#define LEN_RANDOM 		0x03

#define LEN_ADVERTISING (LEN_PROTOCOL_ID + LEN_PRODUCT_ID + LEN_PAYLOAD + LEN_CRC + LEN_RANDOM)

struct stihlAdvData_st
{
	uint8_t protocolID_ui8;
	uint16_t productID_ui16;
	uint8_t payLoad_aui8[LEN_PAYLOAD];
	uint32_t crc32_ui32;
	uint8_t randomNonce[LEN_RANDOM];
};
extern int encryptAdvertising(struct stihlAdvData_st* , struct stihlAdvData_st* );

extern int decrSerialNo_Random(uint8_t*, uint8_t, uint8_t*, uint8_t);
#endif 