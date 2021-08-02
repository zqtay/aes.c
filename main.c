#include "aes.h"
#include "aes_xts.h"

/** AES-XTS testing **/
//Support 2x128 key and 2x256 key

void unitTest(char* strK,   //key in hexstring
              char* strIv,  //iv in hexstring
              char* strPt,  //Plaintext in hexstring 
              char* strCt,  //Ciphertext in hexstring 
              u32 dBit,    //Data length in bits in hexstring 
              u8 kLen)      //AES mode key length
{
  u32 dLen = (dBit % 8) ? (dBit >> 3) + 1 : dBit >> 3; //Input byte size
  u8 k[64];
  u8 iv[16];
  u8 pt[dLen];
  u8 ct[dLen];
  u8 outBuf[dLen]; //Buffer to store cipher output

  //Parse to buffer
  strToArr(strK, k, kLen*2);
  strToArr(strIv, iv, 16);
  strToArr(strPt, pt, dLen);
  strToArr(strCt, ct, dLen);

  printf("Mode: AES%u \n", kLen*8); 
  printf("Input bits: %u \n", dBit); 

  printf("Encryption: \n"); 
  aesXtsEncrypt(pt, dBit, k, kLen, iv, outBuf);
  printArr(outBuf, dLen);
  printf("Verify CT: %u \n", compareArr(outBuf, ct, dLen)); //1 means passed, 0 means failed

  printf("Decryption: \n");
  aesXtsDecrypt(ct, dBit, k, kLen, iv, outBuf);
  printArr(outBuf, dLen);
  printf("Verify PT: %u \n\n", compareArr(outBuf, pt, dLen));
}

/**** Main ****/
int main(){
  printf("AES-XTS tests\n\n");

  //AES128, 384-bit data (3 blocks)
  //TCK310 aes-xts-cipher27 PT4 & CT4
  unitTest(
    "e0e1e2e3e4e5e6e7e8e9eaebecedeeefc0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
    "21436587a90000000000000000000000",
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
    "38b45812ef43a05bd957e545907e223b954ab4aaf088303ad910eadf14b42be68b2461149d8c8ba85f992be970bc621f",
    384,
    AES128_KEY_LEN
  );

  //AES128, 128-bit data (1 block)
  //Test vector 36
  unitTest(
    "55f536b9a09d88855f36ab11ceb56e72491f02b49ce3aa2ce1d9e35da6dc2c6a",
    "6ee0078e34ec33567966f0084cc35273",
    "ef51747b1b1f4917a159eab86044df46",
    "b8c5a5a773c43e720d422ddd679c7b99",
    128,
    AES128_KEY_LEN
  );

  //AES128, 130-bit data (1 block + 2 bits)
  //Test vector 292
  unitTest(
    "77f9325807ef32477b2b0c340528e59cf25e07c0f69c78db1edbd4f4b9aef66f",
    "d8e15b7faba71ad059bb0eb1d14ac7c3",
    "db630e5eb24c2bb5aa8d2114fcf83f9900",
    "30447e2d987b5b7b2f735b13a2db53f4c0",
    130,
    AES128_KEY_LEN
  );
  
  //AES128, 200-bit data (1 block + 9 bytes)
  //Test vector 336
  unitTest(
    "5d773f413dc514f4e64441970a66ac36ddc352924236c948384dd5116ea73b0f",
    "25b3ae8779b8399097a3ead7c4a4b7c1",
    "9d247eef8e3e00fccf519a7e0b61008fd73d2a5a1767721096",
    "245d2528b7e1608a186f6e8d6218ee0b7a73ed9796582419d7",
    200,
    AES128_KEY_LEN
  );

  //AES128, 256-bit data (2 blocks)
  //Test vector 441
  unitTest(
    "151349765b211aa41abf334220a2c6cc8d04a452a35e4f3f6996465844568e89",
    "674fdd744b171361a191d5bc87b1a7d3",
    "44efa575e7bb73cdd6905786507dbd4371c98abc8fb2ef1bdd58ab1b6cb70a49",
    "652c40273b2fb4f5eb8681fce6ff7959067eb9d3bf7a1671072c21c9524243d9",
    256,
    AES128_KEY_LEN
  );

  //AES256, 256-bit data (2 blocks) 
  //Test vector 15
  unitTest(
    "7d797b11bb16634625ed5e1ea909cd2c6c3d2f6b86db5f974d772f04df86972330323a54bbb105c7c0801207439a2e89b73d48cc5c0cb7938a192ee59b8c7547",
    "a3e1477d3b0886eddfe8934f111a2449",
    "63ebae85895f3440c19b563e25f6673f1a519b87ec8d8f80d4afd0dfa5c4d3d3",
    "60977934efa61e51b171cddede3358fd53b6fc13483a690820a484a7ec33c2a8",
    256,
    AES256_KEY_LEN
  );

  //AES256, 140-bit data (1 block + 1 byte + 4 bits)
  //Test vector 298
  unitTest(
    "a6e44763e1a498c63e04dcce60cce8b3894e0315118050c7cfd0e8a747574be203e338247dd4f81689026593647f76ac5b78586c032b17a9c33804a853fd02e2",
    "9cdf213439e0641091875029e13a0784",
    "15f38951bc567f30f2957379e036b223e9a0",
    "acb5abf9874b616ed7f5b53ae2871f68f110",
    140,
    AES256_KEY_LEN
  );

  //AES256, 250-bit data (1 block + 15 bytes + 2 bits)
  //Test vector 321
  unitTest(
    "2ef8ac5ffcaa1ede366170ac3a3f08eb0536afeed906cdccd52cbc03bdfbee20d4d777e9762f16e79796bb853b08aab6a292e8bc52195079544b72fdc27495c5",
    "25d1f22643a546ca757eb4470c6b3252",
    "0b9a790d94ccea09c4cab190c6c84a9d0b82e4f1cabe8a312c5356781ec73b00",
    "fdc6bc8c559a0ae3bb7b23a38f468deda0aca379591b8fa3626c003204b94ec0",
    250,
    AES256_KEY_LEN
  );

  //AES256, 384-bit data (3 blocks)
  //Test vector 405
  unitTest(
    "47ad47c004da79ebf8746a42367b3bb0bcabbf791ab9e388a69692787233f568af82acb58137f2f236dfd917ad6cd2e8fdd0a122706d73e238f4720bbbb17028",
    "44d44c1230173e694dd57b13d7011f3d",
    "3fd99169b740663367ddd0c27f2e53caa7a9f9e0db5b33dd4a0aa5c348a99295b7d5a6a94f7d844e1725589541eb18de",
    "06cc5f87cfdc5d2dd29231595b2cc26017fa57bae64f7a0c71c6b0c7d51fb2cb4fd72727caecd9813478b6c725a4e909",
    384,
    AES256_KEY_LEN
  );
}