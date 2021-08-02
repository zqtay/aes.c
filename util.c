#include "util.h"

/**** Util ****/
void arrToMat(u8* inBuf, u8 outMat[4][4]){
	for(u8 i =0; i<16; i++){
		outMat[i % 4][i >> 2] = inBuf[i];
	}
}

void matToArr(u8 inMat[4][4], u8* outBuf){
	for(u8 i =0; i<16; i++){
		outBuf[i] = inMat[i % 4][i >> 2];
	}
}

void printMat(u8 inMat[4][4]){
	for(u8 i=0;i<4;i++){
		for(u8 j=0; j<4; j++){
			printf("%02x ", inMat[i][j]);
		}
		printf("\n");
	}
}

void printArr(u8* inBuf, u32 len){
	for(u8 i=0;i<len;i++){
    printf("%02x ", inBuf[i]);
	}
  printf("\n");
}

void copyArr(u8* src, u8* dest, u32 len){
  for(u8 i=0; i<len; i++){
    dest[i] = src[i];
  }
}

u8 compareArr(u8* arr1, u8* arr2, u32 len){
  for(u8 i=0; i<len; i++){
    if(arr1[i] != arr2[i]) return 0;
  }
  return 1;
}

void xorArr(u8* arr1, u8* arr2, u32 len) {
  for(u8 i=0; i<len; i++){
    arr1[i] ^= arr2[i];
  }
}





u8 strToHex(char* s){
  u8 a = 0;
  //0-9
  if(*s >= 0x30 && *s <= 0x39) a = (*s - 0x30) << 4;
  //A-F
  else if (*s >= 0x41 && *s <= 0x46) a = (*s - 0x37) << 4;
  //a-f
  else if (*s >= 0x61 && *s <= 0x66) a = (*s - 0x57) << 4;
  else return 0;

  s++;
  if(*s >= 0x30 && *s <= 0x39) a += (*s - 0x30);
  else if (*s >= 0x41 && *s <= 0x46) a += (*s - 0x37);
  else if (*s >= 0x61 && *s <= 0x66) a += (*s - 0x57);
  else return 0;

  return a;
}

void strToArr(char* s, u8* arr, u32 arrLen){
  for(u32 i=0; i<arrLen; i++){
    arr[i] = strToHex(s+(i*2));
  }
}

//Source: https://www.programmersought.com/article/86924783760/
u8 gmul(u8 a, u8 b) {
	u8 p = 0;
	u8 hiBit;
	for(u8 i = 0; i < 8; i++) {
		if(b & 0x01) 
			p ^= a;
		hiBit = a & 0x80;
		a <<= 1;
		if(hiBit == 0x80) 
			a ^= 0x1b;		
		b >>= 1;
	}
	return p;
}
