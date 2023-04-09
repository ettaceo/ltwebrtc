//
// adopted from http://bradconte.com/rc4_c
//
#include <malloc.h>
#include "rc4.h"

// Key Scheduling Algorithm 
// Input: state - the state used to generate the keystream
//        key - Key to use to initialize the state 
//        len - length of key in bytes  
void ksa(unsigned char state[256], unsigned char key[], int len)
{
   int i,j=0,t; 
   
   for (i=0; i < 256; ++i)
      state[i] = i; 
   for (i=0; i < 256; ++i) {
      j = (j + state[i] + key[i % len]) % 256; 
      t = state[i]; 
      state[i] = state[j]; 
      state[j] = t; 
   }   
}

// Pseudo-Random Generator Algorithm 
// Input: state - the state used to generate the keystream 
//        out - Must be of at least "len" length
//        len - number of bytes to generate 
void prga(unsigned char state[], unsigned char out[], int len)
{  
   int i=0,j=0,x,t; 
   //unsigned char key; 
   
   for (x=0; x < len; ++x)  {
      i = (i + 1) % 256; 
      j = (j + state[i]) % 256; 
      t = state[i]; 
      state[i] = state[j]; 
      state[j] = t; 
      out[x] = state[(state[i] + state[j]) % 256];
   }   
}  

void rc4k(unsigned char *key, int key_len, const unsigned char *data, int data_len, unsigned char *result)
{
    unsigned char *cipher;
    unsigned char  state[256];
    int j;

    ksa(state, key, key_len);

    //cipher = (unsigned char *)malloc(data_len);
    cipher = result;  // borrow the space

    prga(state, cipher, data_len);

    for(j = 0; j < data_len; j++)
    {
        //result[j] = data[j] ^ cipher[j];
        result[j] ^= data[j];
    }

    //free(cipher);
}

void rc4init(rc4cx_t *ctx, unsigned char *key, int key_len) 
{
    ksa(ctx->state, key, key_len);
}

void rc4h(rc4cx_t *ctx, const unsigned char *data, int data_len, unsigned char *result)
{
    unsigned char *cipher;
    int  j;

    //cipher = (unsigned char *)malloc(data_len);
    cipher = result;  // borrow the space

    prga(ctx->state, cipher, data_len);

    for(j = 0; j < data_len; j++)
    {
        //result[j] = data[j] ^ cipher[j];
        result[j] ^= data[j];
    }

    //free(cipher);
}


#if TEST_RC4
#include <stdio.h>
/*
Output should be:
EB 9F 77 81 B7 34 CA 72 A7
*/

int main() 
{
   unsigned char state[256],key[]={"Key"},stream[1024]; 
   int len=9,idx; 
   
   ksa(state,key,3); 
   prga(state,stream,len); 
   
   for (idx=0; idx < len; idx++) 
      printf("%02X ",stream[idx]); 
   
   return 0; 
}
#endif // TEXT_RC4