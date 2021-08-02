#include "aes.h"
#include "aes_xts.h"
//http://libeccio.di.unisa.it/Crypto14/Lab/p1619.pdf

void ajMul(u8* inBuf){
  u8 Cin;
  u8 Cout;
  for(u8 i=0; i<16; i++){
    Cout = (inBuf[i] >> 7) & 1;
    inBuf[i] = ((inBuf[i] << 1) + Cin) & 0xFF;
    Cin = Cout;
  }
  if(Cout){
    inBuf[0] ^= GF_128_FDBK;
  }
}

void aesXtsEncrypt(u8* inBuf, u32 inBitLen, u8* key, u8 keyLen, u8* iv, u8* outBuf){
  if(inBitLen < 128) return; //XTS input must be more than 1 block
  if(keyLen != AES128_KEY_LEN && keyLen != AES256_KEY_LEN) return;
  
  u8* key1 = key;
  u8* key2 = key+keyLen;
  u8 partBlock = inBitLen % 128; //Partial block, unit is bit
  u8 pBlkLen = partBlock >> 3;    //Partial block (excluding partial bits), unit is byte
  u8 partByte = partBlock % 8; //Partial bits
  u32 maxRound;
  u8 tempBuf[16];
  u8 T[16];
  u32 i;

  if(partBlock) maxRound = (inBitLen >> 7) - 1;
  else maxRound = inBitLen >> 7;

  aesEncrypt(iv, key2, keyLen, T);

  for(i=0; i < maxRound; i++){
    copyArr(inBuf+(i*16), tempBuf, 16);
    xorArr(tempBuf,T,16);
    aesEncrypt(tempBuf, key1, keyLen, tempBuf);
    xorArr(tempBuf,T,16);
    copyArr(tempBuf, outBuf+(i*16), 16);
    ajMul(T);
  }
  
  if(partBlock) {
    u8 tempBuf2[32];

    //Second last block
    copyArr(inBuf+(i*16), tempBuf, 16);
    //XEX
    xorArr(tempBuf,T,16);
    aesEncrypt(tempBuf, key1, keyLen, tempBuf);
    xorArr(tempBuf,T,16);
    //Multiply aj to use for last block
    ajMul(T);
    //Copy partial byte from tempBuf
    copyArr(tempBuf, tempBuf2+16, pBlkLen);
    //Partial bytes
    if(partByte){
      tempBuf2[16 + pBlkLen] = tempBuf[pBlkLen] & ~(0xFF >> partByte);
    }

    //Last block is a partial block
    //Stealing already done when encrypting second last block
    copyArr(inBuf+(i+1)*16, tempBuf, pBlkLen);
    if(partByte){
      //Preserve the stolen partial byte (lower)
      tempBuf[pBlkLen] &= (0xFF >> partByte);
      //Add the plaintext partial byte (higher)
      tempBuf[pBlkLen] |= inBuf[(i+1)*16 + pBlkLen] & ~(0xFF >> partByte);
    }
    //XEX
    xorArr(tempBuf,T,16);
    aesEncrypt(tempBuf, key1, keyLen, tempBuf);
    xorArr(tempBuf,T,16);
    //Copy second last block output
    copyArr(tempBuf, tempBuf2, 16);

    //Copy to outBuf
    copyArr(tempBuf2, outBuf+(i*16), 16+(pBlkLen));
    if(partByte) outBuf[(i+1)*16 +pBlkLen] = tempBuf2[16+pBlkLen];
  }
}

void aesXtsDecrypt(u8* inBuf, u32 inBitLen, u8* key, u8 keyLen, u8* iv, u8* outBuf){
  if(inBitLen < 128) return; //XTS input must be more than 1 block
  if(keyLen != AES128_KEY_LEN && keyLen != AES256_KEY_LEN) return;

  u8* key1 = key;
  u8* key2 = key+keyLen;
  u8 partBlock = inBitLen % 128; //Partial block, unit is bit
  u8 pBlkLen = partBlock >> 3;    //Partial block (excluding partial bits), unit is byte
  u8 partByte = partBlock % 8; //Partial bits
  u32 maxRound;
  u8 tempBuf[16];
  u8 T[16];
  u32 i;

  if(partBlock) maxRound = (inBitLen >> 7) - 1;
  else maxRound = inBitLen >> 7;

  aesEncrypt(iv, key2, keyLen, T);

  for(i=0; i < maxRound; i++){
    copyArr(inBuf+(i*16), tempBuf, 16);
    xorArr(tempBuf,T,16);
    aesDecrypt(tempBuf, key1, keyLen, tempBuf);
    xorArr(tempBuf,T,16);
    copyArr(tempBuf, outBuf+(i*16), 16);
    ajMul(T);
  }

  if(partBlock) {
    u8 tempBuf2[32];
    //T2 is used to XOR last block
    u8 T2[16];
    copyArr(T,T2,16);
    ajMul(T);

    //Second last block
    copyArr(inBuf+(i*16), tempBuf, 16);
    //XEX
    xorArr(tempBuf,T,16);
    aesDecrypt(tempBuf, key1, keyLen, tempBuf);
    xorArr(tempBuf,T,16);
    //Copy to output last block
    copyArr(tempBuf, tempBuf2+16, pBlkLen);   
    //Copy partial byte from tempBuf
    if(partByte){
      tempBuf2[16+pBlkLen] = tempBuf[pBlkLen] & ~(0xFF >> partByte);
    }

    //Last block is a partial block
    //Stealing already done when encrypting second last block
    copyArr(inBuf+(i+1)*16, tempBuf, pBlkLen);
    if(partByte){
      //Preserve the stolen partial byte (lower)
      tempBuf[pBlkLen] &= (0xFF >> partByte);
      //Add the plaintext partial byte (higher)
      tempBuf[pBlkLen] |= inBuf[(i+1)*16 + pBlkLen] & ~(0xFF >> partByte);
    }
    //XEX
    xorArr(tempBuf,T2,16);
    aesDecrypt(tempBuf, key1, keyLen, tempBuf);
    xorArr(tempBuf,T2,16);
    //Copy to output second last block
    copyArr(tempBuf, tempBuf2, 16);

    //Copy to outBuf
    copyArr(tempBuf2, outBuf+(i*16), 16+(pBlkLen));
    if(partByte) outBuf[(i+1)*16 +pBlkLen] = tempBuf2[16+pBlkLen];
  }
}