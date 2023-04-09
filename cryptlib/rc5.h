// RC5 REF
#ifndef RC5_H_
#define RC5_H_

#ifdef _WIN32
#define inline __inline
#endif

typedef unsigned long int WORD; /* Should be 32-bit = 4 bytes        */

#ifdef __cplusplus
extern "C" {
#endif

void RC5_ENCRYPT(WORD *pt, WORD *ct); /* 2 WORD input pt/output ct    */
void RC5_DECRYPT(WORD *ct, WORD *pt); /* 2 WORD input ct/output pt    */
void RC5_SETUP(unsigned char *K); /* secret input key K[0...b-1]      */

#ifdef __cplusplus
}
#endif

inline void RC5KE(unsigned char*key, char *text, int text_len, char *encrypted)
{
    int k;

    RC5_SETUP(key);  // key must be 16 bytes

    for(k=0; k < text_len; k += 8)
    {
        RC5_ENCRYPT((WORD*)(text + k), (WORD*)(encrypted + k));
    }
}

inline void RC5KD(unsigned char*key, char *text, int text_len, char *dencrypted)
{
    int k;

    RC5_SETUP(key);  // key must be 16 bytes

    for(k=0; k < text_len; k += 8)
    {
        RC5_DECRYPT((WORD*)(text + k), (WORD*)(dencrypted + k));
    }
}

#endif // RC5_H_
