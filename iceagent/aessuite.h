// file : aessuite.h
// date : 04/12/2020
#ifndef AESSUITE_H_
#define AESSUITE_H_

typedef struct aes_parms_t
{
    unsigned char *plaintext_ptr;
    int            plaintext_len;

    unsigned char *ciphertext_ptr;
    int            ciphertext_len;

    unsigned char *aad_ptr;
    int            aad_len;

    unsigned char *tag_ptr;  // 16 bytes

    unsigned char *key_ptr;  // 16/32 bytes per aes cipher suite

    unsigned char *iv_ptr;
    int            iv_len;

}  aes_parms_t;


#ifdef __cplusplus
#extern "C" {
#endif

int gcm_128_decrypt(aes_parms_t *parms);

int gcm_128_encrypt(aes_parms_t *parms);

int    PRF(unsigned char *secret_ptr, int secret_len,
           unsigned char *label_seed_ptr, int label_seed_len,
           unsigned char *out_ptr, int out_len);

#ifdef __cplusplus
}
#endif

#endif  // AESSUITE_H_

