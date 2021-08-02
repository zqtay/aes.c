#include <stdio.h>

typedef unsigned char u8;
typedef unsigned int u32;

void arrToMat(u8* inBuf, u8 outMat[4][4]);
void matToArr(u8 inMat[4][4], u8* outBuf);
void printMat(u8 inMat[4][4]);
void printArr(u8* inBuf, u32 len);
void copyArr(u8* src, u8* dest, u32 len);
u8 compareArr(u8* arr1, u8* arr2, u32 len);
void xorArr(u8* arr1, u8* arr2, u32 len);

u8 strToHex(char* s);
void strToArr(char* s, u8* arr, u32 arrLen);

u8 gmul(u8 a, u8 b);