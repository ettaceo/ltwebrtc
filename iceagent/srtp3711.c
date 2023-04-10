// file srtp3711.c  was rtp_3711.c
// date : 04/18/2020 historic
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <arpa/inet.h>
#include <openssl/hmac.h>
#include "srtp3711.h"
// openssl 1.1.0
#include "openssl/aes.h"
#include "openssl/modes.h"
#include "openssl/rand.h"
#include "openssl/hmac.h"
#include "openssl/sha.h"
#include "openssl/buffer.h"

#define LOGI printf
//#define LOGV printf
#define LOGV(...)

typedef struct ctr_ctx_t
{
    AES_KEY   key;
    unsigned char ivec[AES_BLOCK_SIZE];
    unsigned char ecount[AES_BLOCK_SIZE];
    unsigned int num;
}   ctr_ctx_t;

// @key_length = size of @key in BYTES
void init_ctr_128(ctr_ctx_t *ctx, const u8_t *key, int key_length, const u8_t *iv)
{
    if(key) AES_set_encrypt_key(key, key_length*8, &(ctx->key));
    if(iv) memcpy(ctx->ivec, iv, AES_BLOCK_SIZE);
    memset(ctx->ecount, 0, sizeof(ctx->ecount));
    ctx->num = 0;
}

void crypt_message(const u8_t* src, u8_t* dst, u32_t src_len, ctr_ctx_t *ctx)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    // pre openssl 1.1.0
    AES_ctr128_encrypt(src, dst, src_len, &ctx->key, ctx->ivec, ctx->ecount, &ctx->num);
#else
    // openssl 1.1.0
    CRYPTO_ctr128_encrypt(src, dst, src_len, &ctx->key, ctx->ivec,
                          ctx->ecount, &ctx->num, (block128_f)AES_encrypt);
#endif
}

enum
{
    LABEL_RTP_ENCR,
    LABEL_RTP_SALT,
    LABEL_RTP_AUTH,
    LABEL_RTCP_ENCR,
    LABEL_RTCP_SALT,
    LABEL_RTCP_AUTH
};

typedef struct
{
    unsigned char  cc:4;      // CSRC count
    unsigned char  x:1;       // header extension flag
    unsigned char  p:1;       // padding flag
    unsigned char  version:2; // protocol version

    unsigned char  pt:7;      // payload type
    unsigned char  m:1;       // marker bit

    unsigned short seq;       // sequence number

    u32_t ts;               // timestamp

    u32_t ssrc;             // synchronization source

} rtp_hdr_t;

typedef union
{
    u32_t u32;
    u16_t u16[2];
    u8_t  u8[4];
} dw_t;

// must match srtp profile in select_srtp_profile()
// rfc7714 section 12. AEAD_AES_256_GCM
//#define SRTP_MASTER_KEY_LENGTH  32 // AEAD_AES_256_GCM
#define SRTP_MASTER_KEY_LENGTH  16 // AEAD_AES_128_GCM
#define SRTP_MASTER_SALT_LENGTH 14

typedef struct crypx_t
{
    u32_t  key_length;
    u8_t   master_key[32];
    u8_t   master_salt[16];

    // derived keys - rfc3711 4.3. Key Derivation
    u8_t   rtp_encr[32];
    u8_t   rtp_salt[16];
    u8_t   rtp_auth[20];

    u8_t   rtcp_encr[32];
    u8_t   rtcp_salt[16];
    u8_t   rtcp_auth[20];

    // rtp working area
    u8_t   rtp_enc_iv[16];
    dw_t   rtp_enc_index;
    u32_t  rtp_enc_count;  // @ 30fps, overflow in 4.5 years
//    int  (*rtp_crypt)(struct crypx_t *, void *, int, void *);

    // rtcp working area
    u8_t   rtcp_enc_iv[16];
    dw_t   rtcp_enc_index;
    u32_t  rtcp_enc_count;

//    u8_t   rtcp_dec_iv[16];
//    dw_t   rtcp_dec_index;
//    u32_t  rtcp_dec_count;

//    int  (*rtcp_crypt)(struct crypx_t *, void *, int, void *);

}   crypx_t;

// key derivation - rfc3711 sec 4.3.1
// 1. take packet index 0 DIV by rate 0 get 48-bit 0s
// 2. prefix it with 1-byte label, get 56-bit quantity key-id
// 3. xor key-id with 112-bit master salt, get x
// 4. left-shift x by 16-bit, get 128-bit IV
// 5. encrypt 128-bit 0 as plaintext and 128-bit IV, get derived key
//
int  derive_keys(crypx_t *encx)
{
    int label;
    int i;
    u8_t xtmp[16];

    // let salt be left-most 112 bits
    for( label = 0; label < 6; label++)
    {
        memset(xtmp, 0, sizeof(xtmp));
        xtmp[14-7] = label;  // key-id
        for(i=0; i < 14; i++) xtmp[i] ^= encx->master_salt[i];

        ctr_ctx_t ctx;
        init_ctr_128(&ctx, encx->master_key, encx->key_length, xtmp);

        u8_t zero[32]={(0)};

        switch(label)
        {
        case 0:
            crypt_message(zero, encx->rtp_encr, encx->key_length, &ctx);
            break;
        case 1:
            crypt_message(zero, encx->rtp_auth, 20, &ctx);
            break;
        case 2:
            crypt_message(zero, encx->rtp_salt, 14, &ctx);
            break;
        case 3:
            crypt_message(zero, encx->rtcp_encr, encx->key_length, &ctx);
            break;
        case 4:
            crypt_message(zero, encx->rtcp_auth, 20, &ctx);
            break;
        case 5:
            crypt_message(zero, encx->rtcp_salt, 14, &ctx);
            break;
        default:
            break;
        }
    }

    return 0;
}

int  rtp_header_length(u8_t *rtp)
{
    // ignore header extension for now
    return 12 + ((rtp_hdr_t*)rtp)->cc * 4;
}

static void ssl_hmac_sha1(u8_t * digest, u8_t * key, u32_t keylen,
                          u8_t * text, u32_t textlen)
{
    unsigned int len = 20;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);

    HMAC_Init_ex(&ctx, key, keylen, EVP_sha1(), NULL);
    HMAC_Update(&ctx, text, textlen);
    HMAC_Final(&ctx, digest, &len);
    HMAC_CTX_cleanup(&ctx);
#else
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_CTX_reset(ctx);

    HMAC_Init_ex(ctx, key, keylen, EVP_sha1(), NULL);
    HMAC_Update(ctx, text, textlen);
    HMAC_Final(ctx, digest, &len);
    HMAC_CTX_free(ctx);
#endif
}

static void ssl_hmac_sha1_roc(u8_t * digest, u8_t * key, u32_t keylen,
                              u8_t * text, u32_t textlen, u8_t *roc)
{
    unsigned int len = 20;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);

    HMAC_Init_ex(&ctx, key, keylen, EVP_sha1(), NULL);
    HMAC_Update(&ctx, text, textlen);
    if(roc) HMAC_Update(&ctx, roc, 4);
    HMAC_Final(&ctx, digest, &len);
    HMAC_CTX_cleanup(&ctx);
#else
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_CTX_reset(ctx);

    HMAC_Init_ex(ctx, key, keylen, EVP_sha1(), NULL);
    HMAC_Update(ctx, text, textlen);
    if(roc) HMAC_Update(ctx, roc, 4);
    HMAC_Final(ctx, digest, &len);
    HMAC_CTX_free(ctx);
#endif
}

// @out must have a size of @length + 10 for auth tag calculation
int  encrypt_rtp_128(void *crypx, u8_t *rtp, u32_t length, u8_t *out)
{
    crypx_t *encx = crypx;
    u32_t  hlen;
    u32_t  plen = length;
    int   k;

    if( encx == 0 ) return 0;

    // check that packet_index matches rtp seq

    encx->rtp_enc_index.u32 = htonl(encx->rtp_enc_count);
    // replace low 16-bit with rtp seq in network order
    encx->rtp_enc_index.u16[1] = ((rtp_hdr_t*)rtp)->seq;

    encx->rtp_enc_count += 1;

    // IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16)

    memset(encx->rtp_enc_iv, 0, 16);
    // rfc4.1.1. packet's ssrc
    memcpy(encx->rtp_enc_iv+4, rtp+8, 4);
    // use 32-bit packet index instead of 48-bit
    memcpy(encx->rtp_enc_iv+10, encx->rtp_enc_index.u8, 4);
    // xor with first 14-byte of salt
    for(k=0; k < 14; k++) encx->rtp_enc_iv[k] ^= encx->rtp_salt[k];

    ctr_ctx_t  ctx;

    init_ctr_128(&ctx, encx->rtp_encr, encx->key_length, encx->rtp_enc_iv);

    hlen = rtp_header_length(rtp);

    // unencrypted header
    memcpy(out, rtp, hlen);

    // encrypted payload
    crypt_message(rtp+hlen, out+hlen, plen - hlen, &ctx);

    // authentication tag

    // make ROC
    dw_t roc={0};
    roc.u16[1]=encx->rtp_enc_index.u16[0];

    ssl_hmac_sha1_roc(out + plen, encx->rtp_auth, 20, out, plen, roc.u8);

    plen += 10;

    return plen;;
}

// @rtp must have 4 additional bytes usable for authentication
int  decrypt_rtp_128(void *crypx, u8_t *rtp, u32_t length, u8_t *out)
{
    crypx_t *decx = crypx;
    u32_t  hlen;
    u32_t  plen = length;
    int   k;

    if( decx == 0 ) return 0;

    // check authentication
    unsigned char tag[20];

    decx->rtp_enc_index.u32 = htonl(decx->rtp_enc_count);
    // replace low 16-bit with rtp seq in network order
    decx->rtp_enc_index.u16[1] = ((rtp_hdr_t*)rtp)->seq;

    decx->rtp_enc_count += 1;

    // make ROC
    dw_t roc={0};
    roc.u16[1]=decx->rtp_enc_index.u16[0];

    // authentication tag
    plen = length - 10;

    ssl_hmac_sha1_roc(tag, decx->rtp_auth, 20, rtp, plen, roc.u8);

    if( memcmp(tag, rtp+plen, 10) )
    {
        return -1; // authentication failed
    }

    // IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16)

    memset(decx->rtp_enc_iv, 0, 16);
    // rfc4.1.1. packet's ssrc
    memcpy(decx->rtp_enc_iv+4, rtp+8, 4);
    // use 32-bit packet index instead of 48-bit
    memcpy(decx->rtp_enc_iv+10, decx->rtp_enc_index.u8, 4);
    // xor with first 14-byte of salt
    for(k=0; k < 14; k++) decx->rtp_enc_iv[k] ^= decx->rtp_salt[k];

    ctr_ctx_t  ctx;

    init_ctr_128(&ctx, decx->rtp_encr, decx->key_length, decx->rtp_enc_iv);

    hlen = rtp_header_length(rtp);

    // unencrypted header
    memcpy(out, rtp, hlen);

    // decrypted payload
    crypt_message(rtp+hlen, out+hlen, plen - hlen, &ctx);

    return plen;
}

u32_t encrypt_get_index(void *crypx)
{
    return ((crypx_t *)crypx)->rtcp_enc_count;
}

void encrypt_set_index(void *crypx, u32_t index)
{
    ((crypx_t *)crypx)->rtcp_enc_count = index;
}

#define ENCRYPT_RTCP 1
//
// @out must have a size of @length + 14 for packet index and auth tag bytes
//
int  encrypt_rtcp_128(void *crypx, u8_t *rtcp, u32_t length, u8_t *out)
{
    crypx_t *encx = crypx;
    u32_t  plen = length;
    u32_t  hlen;

    if( encx == 0 ) return 0;

    // check that packet_index matches rtp seq

    // packet index in network order
    encx->rtcp_enc_index.u32 = htonl(encx->rtcp_enc_count);
    // clear e-flag
    encx->rtcp_enc_index.u8[0] &= 0x7f;
    encx->rtcp_enc_count += 1;

#if ENCRYPT_RTCP
    // IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16)
    int   k;

    memset(encx->rtcp_enc_iv, 0, 16);
    // rfc3711 4.1.1 - use first rtcp packet's ssrc
    memcpy(encx->rtcp_enc_iv+4, rtcp+4, 4);
    // use 32-bit packet index instead of 48-bit
    memcpy(encx->rtcp_enc_iv+10, encx->rtcp_enc_index.u8, 4);
    // xor with first 14-byte of salt
    for(k=0; k < 14; k++) encx->rtcp_enc_iv[k] ^= encx->rtcp_salt[k];

    ctr_ctx_t  ctx;

    init_ctr_128(&ctx, encx->rtcp_encr, encx->key_length, encx->rtcp_enc_iv);
#endif
    hlen = 8;

    // unencrypted header
    memcpy(out, rtcp, hlen);
#if ENCRYPT_RTCP
    // encrypted payload
    crypt_message(rtcp+hlen, out+hlen, plen - hlen, &ctx);
#else
    memcpy(out+hlen, rtcp+hlen, plen - hlen);
#endif
    // add e-flag + SRTCP index
    memcpy(out + plen, encx->rtcp_enc_index.u8, 4);
#if ENCRYPT_RTCP
    out[plen] |= 0x80;
#endif
    plen += 4;

    // authentication tag
    ssl_hmac_sha1(out + plen, encx->rtcp_auth, 20, out, plen);
    plen += 10;  // 80-bit auth tag per rfc3711 sec 5.2

    return plen;
}

int  decrypt_rtcp_128(void *crypx, u8_t *rtcp, u32_t length, u8_t *out)
{
    crypx_t *decx = crypx;
    u32_t  plen = length;
    u32_t  hlen;
    int   k;

    if( decx == 0 ) return 0;

    // check authentication
    unsigned char tag[20];
    // authentication tag
    plen = length - 10;
    ssl_hmac_sha1(tag, decx->rtcp_auth, 20, rtcp, plen);

    if( memcmp(tag, rtcp+plen, 10) )
    {
        LOGI("[%s:%u] authentication failed(length=%d)\n", __func__, __LINE__, length);
        return 0; // authentication failed
    }
//LOGI("[%s:%u] authentication ok(length=%d)\n", __func__, __LINE__, length);

    // packet index in network order
    plen -= 4;
    memcpy(decx->rtcp_enc_index.u8, rtcp+plen, 4);
    if( !(decx->rtcp_enc_index.u8[0] & 0x80) )
    {
        // e-flag not set
        memcpy(out, rtcp, plen);
        return plen;
    }

    // clear e-flag
    decx->rtcp_enc_index.u8[0] &= 0x7f;

    decx->rtcp_enc_count += 1;

    // IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16)

    memset(decx->rtcp_enc_iv, 0, 16);
    // rfc3711 4.1.1 - use first rtcp packet's ssrc
    memcpy(decx->rtcp_enc_iv+4, rtcp+4, 4);
    // use 32-bit packet index instead of 48-bit
    memcpy(decx->rtcp_enc_iv+10, decx->rtcp_enc_index.u8, 4);
    // xor with first 14-byte of salt
    for(k=0; k < 14; k++) decx->rtcp_enc_iv[k] ^= decx->rtcp_salt[k];

    ctr_ctx_t  ctx;

    init_ctr_128(&ctx, decx->rtcp_encr, decx->key_length, decx->rtcp_enc_iv);

    hlen = 8;

    // unencrypted header
    memcpy(out, rtcp, hlen);

    // decrypt payload
    crypt_message(rtcp+hlen, out+hlen, plen - hlen, &ctx);

    return plen;
}

// @key_length = length of @master_key in BYTES
void * init_srtp_crypt(u8_t *master_key, int key_length, u8_t *master_salt)
{
    crypx_t *crypx;

    if( key_length != 16 &&  key_length != 24 && key_length != 32 ) return 0;

    crypx = calloc(1, sizeof(crypx_t));

    crypx->key_length = key_length;
    memcpy(crypx->master_key, master_key, key_length);
    memcpy(crypx->master_salt, master_salt, 14);

    derive_keys(crypx);

    return crypx;
}

void * free_srtp_crypt(void *crypx)
{
    if( crypx ) free(crypx);

    return 0;
}

////////////////////////////////////////////////////////////////////////////////
//#define LOGV printf

#ifdef LOCAL_BUILD

static int hex2bin(const char *hex, unsigned char *bin)
{
    int e;
    int n;

    for(e = 0, n=(int)strlen(hex)/2; e < n ; e++)
    {
        sscanf(hex+2*e, "%2hhx", bin+e);
    }
    return e;
}
// @col = number of columns
static void dump_hex(unsigned char *txt, int len, int col)
{
    int k, i;

    for(i=0, k = 0; k < len; k++)
    {
        printf("%.2x ", txt[k]);
        if( ++i == col )
        {
            printf("\n");
            i=0;
        }
    }
    printf("\n");
}

//const char *mk_hex="f0f04914b513f2763a1b1fa130f10e2998f6f6e43e4309d1e622a0e332b9f1b6";
//const char *ms_hex="3b04803de51ee7c96423ab5b78d2";
const char *mk_hex="E1F97A0D3E018BE0D64FA32C06DE4139";
const char *ms_hex="0EC675AD498AFEEBB6960B3AABE6";

int main(int argc, char *argv[])
{
    crypx_t *encx;
    crypx_t *decx;
    unsigned char   mk_bin[32];
    unsigned char   ms_bin[16];
    int    kl;

    kl = hex2bin(mk_hex, mk_bin);
    hex2bin(ms_hex, ms_bin);

    encx = init_srtp_crypt(mk_bin, kl, ms_bin);
    dump_hex(encx->rtp_encr, kl, 0);
    dump_hex(encx->rtp_auth, 20, 0);
    dump_hex(encx->rtp_salt, 14, 0);
    decx = init_srtp_crypt(mk_bin, kl, ms_bin);
 
    if( argc > 1 )
    {
        FILE *f = fopen(argv[1], "r");
        if( f )
        {
            char *hex=malloc(4096);
            unsigned char *rtp=malloc(2048);
            unsigned char *out=malloc(2048);
            int len;
            len = fread(hex, 1, 4096, f);
            if( len > 0 )
            {
                len = hex2bin(hex, rtp);
                printf(" enc input len=%d\n", len);
                dump_hex(rtp, len, 32);
                len = encrypt_rtp_128(encx, rtp, len, out);
                printf(" enc output len=%d\n", len);
                dump_hex(out, len, 32);
                //
                len = decrypt_rtp_128(decx, out, len, rtp);
                printf(" dec len=%d\n", len);
                dump_hex(rtp, len, 32);
            }

            free(out);
            free(rtp);
            free(hex);
            fclose(f);
        }
        else printf("open %s failed\n", argv[1]);
    }
    else printf("usage: %s <hex>\n", argv[0]);

    free_srtp_crypt(encx);
    free_srtp_crypt(decx);
    
    return 0;
}
#endif // LOCAL_BUILD
