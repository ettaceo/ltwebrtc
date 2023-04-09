// file : aessuite.c
// date : 04/12/2020
// https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aessuite.h"

#include "openssl/evp.h"
#include "openssl/kdf.h"     // PRF

#define LOGV printf

//
// @parms->cipher_ptr must be a valid pointer to enough memory to write to
//
int gcm_128_encrypt(aes_parms_t *parms)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len=0;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        LOGV("[%s:%u] PANIC!\n", __func__, __LINE__);
        goto exit;
    }

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), 0, 0, 0))
    {
        LOGV("[%s:%u] PANIC!\n", __func__, __LINE__);
        goto exit;
    }

    /*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
     */
    // preferred EVP_CTRL_AEAD_SET_IVLEN
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, parms->iv_len, 0))
    {
        LOGV("[%s:%u] PANIC!\n", __func__, __LINE__);
        goto exit;
    }

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, 0, 0, parms->key_ptr, parms->iv_ptr))
    {
        LOGV("[%s:%u] PANIC!\n", __func__, __LINE__);
        goto exit;
    }

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(1 != EVP_EncryptUpdate(ctx, 0, &len, parms->aad_ptr, parms->aad_len))
    {
        LOGV("[%s:%u] PANIC!\n", __func__, __LINE__);
        goto exit;
    }

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, parms->ciphertext_ptr, &len,
                              parms->plaintext_ptr, parms->plaintext_len))
    {
        LOGV("[%s:%u] PANIC!\n", __func__, __LINE__);
        goto exit;
    }
    ciphertext_len = len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, parms->ciphertext_ptr + len, &len))
    {
        LOGV("[%s:%u] PANIC!\n", __func__, __LINE__);
        goto exit;
    }
    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, parms->tag_ptr))
    {
        LOGV("[%s:%u] PANIC!\n", __func__, __LINE__);
        goto exit;
    }

exit:
    /* Clean up */
    if( ctx ) EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

//
// @parms->plaintext_ptr must be a valid pointer to enough memory to write to
//
int gcm_128_decrypt(aes_parms_t *parms)
{
    EVP_CIPHER_CTX *ctx=0;
    int plaintext_len=0;
    int len=0;
    int ret=0;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        LOGV("[%s:%u] PANIC!\n", __func__, __LINE__);
        goto exit;
    }

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), 0, 0, 0))
    {
        LOGV("[%s:%u] PANIC!\n", __func__, __LINE__);
        goto exit;
    }

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    // preferred EVP_CTRL_AEAD_SET_IVLEN
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, parms->iv_len, 0))
    {
        LOGV("[%s:%u] PANIC!\n", __func__, __LINE__);
        goto exit;
    }

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, 0, 0, parms->key_ptr, parms->iv_ptr))
    {
        LOGV("[%s:%u] PANIC!\n", __func__, __LINE__);
        goto exit;
    }

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(!EVP_DecryptUpdate(ctx, 0, &len, parms->aad_ptr, parms->aad_len))
    {
        LOGV("[%s:%u] PANIC!\n", __func__, __LINE__);
        goto exit;
    }

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(!EVP_DecryptUpdate(ctx, parms->plaintext_ptr, &len,
                          parms->ciphertext_ptr, parms->ciphertext_len))
    {
        goto exit;
    }

    plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, parms->tag_ptr))
    {
        LOGV("[%s:%u] PANIC!\n", __func__, __LINE__);
        goto exit;
    }

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, parms->plaintext_ptr + len, &len);

exit:
    /* Clean up */
    if( ctx) EVP_CIPHER_CTX_free(ctx);

    if(ret > 0)
    {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    } 
    else
    {
        /* Verify failed */
        return -1;
    }
}

// rfc5246 sec 5. sha265 hashing
int    PRF(unsigned char *secret_ptr, int secret_len,
           unsigned char *label_seed_ptr, int label_seed_len,
           unsigned char *out_ptr, int out_len)
{
    int e=0;

    EVP_PKEY_CTX *pctx;
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, NULL);
    if (EVP_PKEY_derive_init(pctx) <= 0)
    {
        LOGV("[%s:%u] PANIC!\n", __func__, __LINE__);
        goto exit;
    }
    e = EVP_PKEY_CTX_set_tls1_prf_md(pctx, EVP_sha256());
    if( e <= 0 )
    {
        LOGV("[%s:%u] PANIC!\n", __func__, __LINE__);
        goto exit;
    }
    e = EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, secret_ptr, secret_len);
    if( e <= 0 )
    {
        LOGV("[%s:%u] PANIC!\n", __func__, __LINE__);
        goto exit;
    }
    e = EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, label_seed_ptr, label_seed_len);
    if( e <= 0 )
    {
        LOGV("[%s:%u] PANIC!\n", __func__, __LINE__);
        goto exit;
    }
    size_t out_size = out_len;
    e = EVP_PKEY_derive(pctx, out_ptr, &out_size);
    if( e <= 0 || out_len != (int)out_size )
    {
        LOGV("[%s:%u] PANIC! out_len=%d out_size=%d \n", __func__, __LINE__,
            out_len, (int)out_size);
        goto exit;
    }
    e = out_len;

exit:
    if( pctx ) EVP_PKEY_CTX_free(pctx);

    return e;
}

////////////////////////////////////////////////////////////////////////////////
#ifdef LOCAL_BUILD

#define TEST_PRF
#define TEST_AES_128_GCM

#ifdef TEST_AES_128_GCM
//
// Cipher = aes-128-gcm
// Key = feffe9928665731c6d6a8f9467308308
// IV = cafebabefacedbaddecaf888
// AAD = feedfacedeadbeeffeedfacedeadbeefabaddad2
// Tag = 5bc94fbc3221a5db94fae95ae7121a47
// Plaintext = d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39
// Ciphertext = 42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091

static unsigned char key[]=
{0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08};

static unsigned char iv[]=
{0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,0xde,0xca,0xf8,0x88};

static unsigned char aad[]=
{0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,
 0xab,0xad,0xda,0xd2};

static unsigned char tag[]=
{0x5b,0xc9,0x4f,0xbc,0x32,0x21,0xa5,0xdb,0x94,0xfa,0xe9,0x5a,0xe7,0x12,0x1a,0x47};

static unsigned char plaintext[]=
{0xd9,0x31,0x32,0x25,0xf8,0x84,0x06,0xe5,0xa5,0x59,0x09,0xc5,0xaf,0xf5,0x26,0x9a,
 0x86,0xa7,0xa9,0x53,0x15,0x34,0xf7,0xda,0x2e,0x4c,0x30,0x3d,0x8a,0x31,0x8a,0x72,
 0x1c,0x3c,0x0c,0x95,0x95,0x68,0x09,0x53,0x2f,0xcf,0x0e,0x24,0x49,0xa6,0xb5,0x25,
 0xb1,0x6a,0xed,0xf5,0xaa,0x0d,0xe6,0x57,0xba,0x63,0x7b,0x39};

static unsigned char ciphertext[]=
{0x42,0x83,0x1e,0xc2,0x21,0x77,0x74,0x24,0x4b,0x72,0x21,0xb7,0x84,0xd0,0xd4,0x9c,
 0xe3,0xaa,0x21,0x2f,0x2c,0x02,0xa4,0xe0,0x35,0xc1,0x7e,0x23,0x29,0xac,0xa1,0x2e,
 0x21,0xd5,0x14,0xb2,0x54,0x66,0x93,0x1c,0x7d,0x8f,0x6a,0x5a,0xac,0x84,0xaa,0x05,
 0x1b,0xa3,0x0b,0x39,0x6a,0x0a,0xac,0x97,0x3d,0x58,0xe0,0x91};

#endif // #ifdef TEST_AES_128_GCM

#ifdef TEST_AES_128_CTR

#endif // TEST_AES_128_CTR

static void dump_hex(uint8_t *hex, int len)
{
    int j;
    for(j = 0;  j < len; j++)
    {
        if( j>0 && (j%16==0) ) printf("\n");
        printf("%.2x ", hex[j]);
    }
    printf("\n"); 
}

int main(int argc, char *argv[])
{
    aes_parms_t *parms=__builtin_alloca(sizeof(aes_parms_t));
    __builtin_memset(parms, 0, sizeof(aes_parms_t));

    parms->ciphertext_ptr = ciphertext;
    parms->ciphertext_len = sizeof(ciphertext);

    parms->key_ptr = key;

    parms->iv_ptr = iv;
    parms->iv_len = sizeof(iv);

    parms->aad_ptr = aad;
    parms->aad_len = sizeof(aad);
    
    parms->tag_ptr = tag;

    int len=0;

#ifdef TEST_AES_128_GCM
    parms->plaintext_ptr = __builtin_alloca(parms->ciphertext_len+16);
    parms->plaintext_len = parms->ciphertext_len+16;
    len = gcm_128_decrypt(parms);
#endif
    if( len > 0 )
    {
        LOGV("{main} decrypted len=%d\n", len);
        dump_hex(parms->plaintext_ptr, len);
    }

    parms->ciphertext_ptr = __builtin_alloca(parms->plaintext_len);
    parms->ciphertext_len = parms->plaintext_len;
    
    parms->plaintext_ptr = plaintext;
    parms->plaintext_len = sizeof(plaintext);

#ifdef TEST_AES_128_GCM
    parms->tag_ptr = __builtin_alloca(16);
     __builtin_memset(parms->tag_ptr, 0, 16);
    len = gcm_128_encrypt(parms);
#endif

    if( len > 0 )
    {
        LOGV("{main} encrypted len=%d\n", len);
        dump_hex(parms->ciphertext_ptr, len);
        LOGV("{main} encrypted tag:\n");
        dump_hex(parms->tag_ptr, 16);
    }

#ifdef TEST_PRF
    // tls1.2-prf-test-vectors.txt
    unsigned char secret[]=
    {
        0x9b, 0xbe, 0x43, 0x6b, 0xa9, 0x40, 0xf0, 0x17,
        0xb1, 0x76, 0x52, 0x84, 0x9a, 0x71, 0xdb, 0x35
    };
    unsigned char label_seed[]=
    {
        0x74, 0x65, 0x73, 0x74, 0x20, 0x6c, 0x61, 0x62,   // test lab
        0x65, 0x6c,                                       // el
        0xa0, 0xba, 0x9f, 0x93, 0x6c, 0xda, 0x31, 0x18,   // <seed>
        0x27, 0xa6, 0xf7, 0x96, 0xff, 0xd5, 0x19, 0x8c    //
    };
    // Output (100 bytes):
    // 0000    e3 f2 29 ba 72 7b e1 7b 8d 12 26 20 55 7c d4 53
    // 0010    c2 aa b2 1d 07 c3 d4 95 32 9b 52 d4 e6 1e db 5a
    // 0020    6b 30 17 91 e9 0d 35 c9 c9 a4 6b 4e 14 ba f9 af
    // 0030    0f a0 22 f7 07 7d ef 17 ab fd 37 97 c0 56 4b ab
    // 0040    4f bc 91 66 6e 9d ef 9b 97 fc e3 4f 79 67 89 ba
    // 0050    a4 80 82 d1 22 ee 42 c5 a7 2e 5a 51 10 ff f7 01
    // 0060    87 34 7b 66

    unsigned char out[100];

    int k = PRF(secret, sizeof(secret), label_seed, sizeof(label_seed),
                out, sizeof(out));
    LOGV("[%s:%u] PRF out_len=%d\n", __func__, __LINE__, k);
    dump_hex(out, sizeof(out));

#endif // TEST_PRF

    return 0;
}

#endif
