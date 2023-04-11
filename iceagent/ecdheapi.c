// file : ecdheapi.c
// date : 04/05/2020
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "ecdheapi.h"

//#include "openssl/crypto.h"
#include "openssl/evp.h"
#include "openssl/ec.h"

#define LOGV(...)
//#define LOGV printf

typedef struct ec_ctx_t
{
    int       ec_named_curve;  // rfc8422 5.1.1. secp256r1=0x0017 (23)
    int       public_key_length;
    uint8_t  *public_key_string; // to be freed by OPENSSL_free()
    EVP_PKEY *pkey;  // private key struct, to be freed by EVP_PKEY_free() 

} ec_ctx_t;

#define MAX_EC_KEYS   8
static ec_ctx_t g_ec_ctx[MAX_EC_KEYS];

static EVP_PKEY *make_ecdh_keypair(int named_curve)
{
	EVP_PKEY_CTX *pctx=0, *kctx=0;
	EVP_PKEY *pkey=0, *params=0;

	// Create the context for parameter generation
	if(0 == (pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, 0)))
    {
        goto exit;
    }

	// Initialize the parameter generation
	if(1 != EVP_PKEY_paramgen_init(pctx))
    {
        goto exit;
    }

    int nid = -1;
    switch(named_curve)
    {
    case 0x0017:  // "secp256r1" rfc8422
        // ANSI X9.62 Prime 256v1 curve = secp256r1 ref. rfc5480
        nid = NID_X9_62_prime256v1;
        break;
    default:
        break;
    }
    if( nid == -1 )
    {
        goto exit;
    }
    
	if(1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, nid))
    {
        goto exit;
    }

	// Create the parameter object params
	if (!EVP_PKEY_paramgen(pctx, &params))
    {
        goto exit;
    }

	// Create the context for the key generation
	if(0 == (kctx = EVP_PKEY_CTX_new(params, 0)))
    {
        goto exit;
    }

	// Generate the key pair
	if(1 != EVP_PKEY_keygen_init(kctx))
    {
        goto exit;
    }
	if (1 != EVP_PKEY_keygen(kctx, &pkey))
    {
        goto exit;
    }

exit:
//	if( pkey ) EVP_PKEY_free(pkey);
	if( kctx ) EVP_PKEY_CTX_free(kctx);
	if( params ) EVP_PKEY_free(params);
	if( pctx ) EVP_PKEY_CTX_free(pctx);

	return pkey;
}

//
// on successful return, @buf must be freed by OPENSSL_free()
//
static int get_ec_public_key(EVP_PKEY *pkey, uint8_t **buf)
{
    int klen = -1;
    EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);

    if( ec_key == 0 ) goto exit;

    BN_CTX *bn_ctx = BN_CTX_new();

    size_t size = EC_KEY_key2buf(
                     ec_key,
                     POINT_CONVERSION_UNCOMPRESSED,
                     buf, 
                     bn_ctx);

    BN_CTX_free(bn_ctx);

    klen = (int)size;

exit:
    return klen;
}

//
// @key_oct : peer ec public key
//
static EVP_PKEY * make_ecdh_peerkey(int named_curve, uint8_t *key_oct, int key_len)
{
	EVP_PKEY     *pkey = 0;
    EC_KEY       *key = 0;
    int  e;

    int nid = -1;
    switch(named_curve)
    {
    case 0x0017:  // "secp256r1" rfc8422
        // ANSI X9.62 Prime 256v1 curve = secp256r1 ref. rfc5480
        nid = NID_X9_62_prime256v1;
        break;
    default:
        break;
    }
    if( nid == -1 )
    {
        LOGV("[%s:%u] PANIC!\n", __func__, __LINE__);
        goto exit;
    }

    key = EC_KEY_new_by_curve_name(nid);

    if( 0 == key )
    {
        LOGV("[%s:%u] PANIC!\n", __func__, __LINE__);
        goto exit;
    }

    const EC_GROUP *group = EC_KEY_get0_group(key);

    EC_POINT *point = EC_POINT_new(group);
    if( 0 == point )
    {
        LOGV("[%s:%u] PANIC!\n", __func__, __LINE__);
        goto exit;
    }
    BN_CTX *bn_ctx = BN_CTX_new();
    e = EC_POINT_oct2point(group, point, key_oct, key_len, bn_ctx);
    BN_CTX_free(bn_ctx);

    if( 1 != e )
    {
        LOGV("[%s:%u] PANIC!\n", __func__, __LINE__);
        goto exit;
    }
    e = EC_KEY_set_public_key(key, point);
    EC_POINT_free(point);
    if( 1 != e )
    {
        LOGV("[%s:%u] PANIC!\n", __func__, __LINE__);
        goto exit;
    }

    pkey = EVP_PKEY_new();
    if( 0 == pkey )
    {
        LOGV("[%s:%u] PANIC!\n", __func__, __LINE__);
        goto exit;
    }

    //
    e = EVP_PKEY_set1_EC_KEY(pkey, key);
    if( 1 != e )
    {
        LOGV("[%s:%u] PANIC!\n", __func__, __LINE__);
        goto exit;
    }

exit:
    // free ec key
    if( key ) EC_KEY_free(key);

	return pkey;
}

////////////////////////////////////////////////////////////////////////////////

static pthread_mutex_t ec_lock=PTHREAD_MUTEX_INITIALIZER;

void * init_ec_keypair(void)
{
    ec_ctx_t *ec_ctx=0;
    
    pthread_mutex_lock(&ec_lock);
    // find a slot
    int j;
    for( j = 0; j < MAX_EC_KEYS; j++ )
    {
        if( g_ec_ctx[j].pkey == 0 )
        {
            ec_ctx = g_ec_ctx+j;
            break;
        }
    }
    
    if( ec_ctx )
    {
        // set curve group "secp256r1"
        ec_ctx->ec_named_curve = 0x0017; // rfc8422 5.1.1.
        // create key pair
        ec_ctx->pkey = make_ecdh_keypair(ec_ctx->ec_named_curve);
        // export public key
        ec_ctx->public_key_length =
            get_ec_public_key(ec_ctx->pkey, &ec_ctx->public_key_string);
    }

    pthread_mutex_unlock(&ec_lock);

    return ec_ctx;
}

void   exit_ec_keypair(void *ctx)
{
    ec_ctx_t *ec_ctx = ctx;

    pthread_mutex_lock(&ec_lock);

    if( ec_ctx )
    {
        if( ec_ctx->public_key_string)
        {
            OPENSSL_free(ec_ctx->public_key_string);
            ec_ctx->public_key_string = 0;
            ec_ctx->public_key_length = 0;
            LOGV("[%s:%u] ec public key freed\n", __func__, __LINE__);
        }
        if( ec_ctx->pkey )
        {
            EVP_PKEY_free(ec_ctx->pkey);
            ec_ctx->pkey = 0;
            LOGV("[%s:%u] ec private key freed\n", __func__, __LINE__);
        }
    }

    pthread_mutex_unlock(&ec_lock);
}

int    copy_ec_pub_key(void *ctx, uint8_t *buf, int len)
{
    ec_ctx_t *ec_ctx = ctx;

    if( ec_ctx->public_key_length > 0 )
    {
        if( ec_ctx->public_key_length <= len && buf )
        {
            memcpy(buf, ec_ctx->public_key_string, ec_ctx->public_key_length);
        }
    }
    
    return ec_ctx->public_key_length;
}

int    get_curved_name(void *ctx)
{
    ec_ctx_t *ec_ctx = ctx;

    return ec_ctx->ec_named_curve;
}

// derive session shared secret with self private key and peer public key
int    calc_pre_master(void *ctx, uint8_t *pubk, int klen, uint8_t *secret)
{
    ec_ctx_t     *ec_ctx = ctx;
    EVP_PKEY     *pp_key = 0;
    EVP_PKEY_CTX *ss_ctx=0;  // shared secret context
    size_t        ss_len=0;
    int e;

	ss_ctx = EVP_PKEY_CTX_new(ec_ctx->pkey, 0);
    if( 0 == ss_ctx)
    {
        LOGV("[%s:%u] PANIC!\n", __func__, __LINE__);
        goto exit;
    }

	e = EVP_PKEY_derive_init(ss_ctx);
	if(1 != e)
    {
        LOGV("[%s:%u] PANIC!\n", __func__, __LINE__);
        goto exit;
    }

    // create a EVP_PKEY struct from peer
    pp_key = make_ecdh_peerkey(ec_ctx->ec_named_curve, pubk, klen);
	if(0 == pp_key)
    {
        LOGV("[%s:%u] PANIC! peer_len=%d\n", __func__, __LINE__, klen);
        goto exit;
    }

	e = EVP_PKEY_derive_set_peer(ss_ctx, pp_key);
	if(1 != e)
    {
        LOGV("[%s:%u] PANIC!\n", __func__, __LINE__);
        goto exit;
    }

    e = EVP_PKEY_derive(ss_ctx, 0, &ss_len);
	if(1 != e)
    {
        LOGV("[%s:%u] PANIC!\n", __func__, __LINE__);
        goto exit;
    }

    if( secret == 0 ) goto exit;  // return secret length

	e = EVP_PKEY_derive(ss_ctx, secret, &ss_len);

exit:
    if( pp_key ) EVP_PKEY_free(pp_key);
	if( ss_ctx) EVP_PKEY_CTX_free(ss_ctx);

    return (int)ss_len;
}

#ifdef LOCAL_BUILD

static void dump_hex(uint8_t *hex, int len)
{
    int j;
    for(j = 0;  j < len; j++)
    {
        if( j>0 && (j%16==0) ) printf("\n");
        printf("%.2x ", hex[j]);
    }
    if( j%16) printf("\n"); 
}

int main(int argc, char *argv[])
{
    ec_ctx_t *ctx = init_ec_keypair();

    LOGV("[%s:%u] curve=%d klen=%d\n", __func__, __LINE__,
        ctx->ec_named_curve, ctx->public_key_length);
    if( ctx->public_key_length > 0 )
        dump_hex(ctx->public_key_string, ctx->public_key_length);

    exit_ec_keypair(ctx);
    
    return 0;
}

#endif // LOCAL_BUILD
