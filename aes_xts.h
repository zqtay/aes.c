#include "util.h"
#include "aes.h"

#define GF_128_FDBK 0x87

void ajMul(u8* inBuf);
void aesXtsEncrypt(u8* inBuf, u32 inBitLen, u8* key, u8 keyLen, u8* iv, u8* outBuf);
void aesXtsDecrypt(u8* inBuf, u32 inBitLen, u8* key, u8 keyLen, u8* iv, u8* outBuf);