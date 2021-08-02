#include "util.h"

//Now only support 128 & 256

#define AES128_ROUND 10
#define AES128_KEY_LEN 16
#define AES128_EXPKEY_ROUND 10

#define AES192_ROUND 12
#define AES192_KEY_LEN 24
#define AES192_EXPKEY_ROUND 8

#define AES256_ROUND 14
#define AES256_KEY_LEN 32
#define AES256_EXPKEY_ROUND 7


// Functions
void subBytes(u8 inMat[4][4]);
void invSubBytes(u8 inMat[4][4]);
void shiftRows(u8 inMat[4][4]);
void invShiftRows(u8 inMat[4][4]);
void mixColumns(u8 inMat[4][4]);
void invMixColumns(u8 inMat[4][4]);
void addRoundKey(u8 inMat[4][4], u8* key);

u8 rcon(u8 round);
void g(u8* w, u8 round);
void expandKey128(u8* key, u8 round, u8* outKey);
void expandKey256(u8* key, u8 round, u8* outKey);

void aesEncrypt(u8* inBuf, u8* key, u8 keyLen, u8* outBuf);
void aesDecrypt(u8* inBuf, u8* key, u8 keyLen, u8* outBuf);