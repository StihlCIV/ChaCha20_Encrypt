#ifndef __CHACHA20_H
#define __CHACHA20_H
#define PROTOCOL_ID 0x16
#define PRODUCT_ID 0x05

#define LEN_SERIAL_NO 32

// #define CHECK_16
#ifdef CHECK_16 
    #define LEN_CRC 0x02
#else
    #define LEN_CRC 0x04
#endif 
#define LEN_ENCRYPTED (LEN_SERIAL_NO + LEN_CRC)
#define LEN_RANDOM 0x03
#define LEN_TX_DATA (LEN_ENCRYPTED + LEN_RANDOM)


extern int encrSerialNo_Random(uint8_t*, uint8_t, uint8_t*, uint8_t);

extern int decrSerialNo_Random(uint8_t*, uint8_t, uint8_t*, uint8_t);
#endif 