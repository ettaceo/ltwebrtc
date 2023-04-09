#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "x509cert.h"
#include "openssl/x509.h"
#include "openssl/crypto.h"
#include "openssl/pem.h"
#include "openssl/conf.h"
#include "openssl/x509v3.h"
#ifndef OPENSSL_NO_ENGINE
#include "openssl/engine.h"
#endif

#define LOGV printf

enum e_cert_key_algorithm
{
    e_key_algo_none = 0,
    e_key_algo_rsa  = 1,
    e_key_algo_dsa  = 2,
    e_key_algo_ec,
    e_key_algo_max
};

typedef struct cert_info_t
{
    X509      *x509;      // certificate
    EVP_PKEY  *pkey;      // key pair
    const EVP_MD *digest;    // hash algorithm

    int        key_algo;  // rsa:1, dsa:2, ec:3
    int        key_bits;  // rsa:512-2048, dsa:512-2046, ec:256
    int        serial;    // 1
    int        days;      // 365

}  cert_info_t;

/* Add extension using V3 code: we can set the config file as NULL
 * because we wont reference any other sections.
 */
__attribute__((unused))
static int add_ext(X509 *cert, int nid, char *value)
{
	X509_EXTENSION *ex;
	X509V3_CTX ctx;
	/* This sets the 'context' of the extensions. */
	/* No configuration database */
	X509V3_set_ctx_nodb(&ctx);
	/* Issuer and subject certs: both the target since it is self signed,
	 * no request and no CRL
	 */
	X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	if (!ex)
		return 0;

	X509_add_ext(cert,ex,-1);
	X509_EXTENSION_free(ex);
	return 1;
}

static int set_rsa_key_pair(cert_info_t *info)
{
    BIGNUM *e;
	e = BN_new();
	RSA *rsa = RSA_new();
	BN_set_word(e, RSA_F4);
	int rc = RSA_generate_key_ex(rsa, info->key_bits, e, 0);
	BN_free(e);
	if( rc != 1 ) goto error;

	rc = EVP_PKEY_assign_RSA(info->pkey, rsa);
	
	if(rc != 1 )  goto error;

	rsa=NULL;

	return 1; // ok
error:
	RSA_free(rsa);
    return 0;
}

static int set_dsa_key_pair(cert_info_t *info)
{
	DSA *dsa = DSA_new();
	int rc = DSA_generate_parameters_ex(dsa, info->key_bits, 0, 0, 0, 0, 0);
	if( rc != 1 ) goto error;

	rc = DSA_generate_key(dsa);
	if( rc != 1 ) goto error;

	rc = EVP_PKEY_assign_DSA(info->pkey, dsa);
	if( rc != 1 ) goto error;

	dsa=NULL;

	return 1; // ok
error:
    DSA_free(dsa);
    return 0;
}

static int set_ec_key_pair(cert_info_t *info)
{
	EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	
	int rc = EC_KEY_generate_key(ec);
	if( rc != 1 ) goto error;

	rc = EVP_PKEY_assign_EC_KEY(info->pkey, ec);
	if( rc != 1 ) goto error;

	ec=NULL;

	return 1; // ok
error:
    EC_KEY_free(ec);
    return 0;
}

static int make_certificate(cert_info_t *info)
{
    if( info->key_algo <= e_key_algo_none ||
        info->key_algo >= e_key_algo_max )
    {
		return -1; // must set key algorithm
	}

	if( info->key_bits <= 0 )
	{
		info->key_bits = (info->key_algo == e_key_algo_ec ? 256 : 512);
	}
	
	if( info->days <= 0 ) info->days = 365;
	
	if( info->pkey == 0 ) info->pkey = EVP_PKEY_new();

    if( info->pkey == 0 ) return -2;
	
	if( info->x509 == 0 ) info->x509 = X509_new();

    if( info->x509 == 0 ) return -3;
	
	int rc = - 9;
	
	switch( info->key_algo )
	{
	case e_key_algo_rsa:
	    rc = set_rsa_key_pair(info);
	    info->digest = EVP_sha256();
	    break;
	case e_key_algo_dsa:
	    rc = set_dsa_key_pair(info);
	    info->digest = EVP_sha1();
	    break;
	case e_key_algo_ec:
	    rc = set_ec_key_pair(info);
	    info->digest = EVP_sha256();
	    break;
	default:
	    break;
	}
    if( rc <= 0 ) goto error;
    
	X509_set_version(info->x509, 2); // v3
	
	ASN1_INTEGER_set(X509_get_serialNumber(info->x509), info->serial);

	X509_gmtime_adj(X509_get_notBefore(info->x509), 0);

	X509_gmtime_adj(X509_get_notAfter(info->x509), (long)60*60*24*info->days);

	X509_set_pubkey(info->x509, info->pkey);

	X509_NAME *name = X509_get_subject_name(info->x509);

	/* This function creates and adds the entry, working out the
	 * correct string type and performing checks on its length.
	 * Normally we'd check the return value for errors...
	 */
#if 0
    // Country is not needed for webrtc
	X509_NAME_add_entry_by_txt(name,"C",
				MBSTRING_ASC, (uint8_t*)"UN", -1, -1, 0);
#endif
	X509_NAME_add_entry_by_txt(name,"CN",
				MBSTRING_ASC, (uint8_t*)"ivyrtc", -1, -1, 0);

	/* Its self signed so set the issuer name to be the same as the
 	 * subject.
	 */
	X509_set_issuer_name(info->x509, name);
#if 0
    // chrome for Linux in the case of TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    // and chrome for Windows for both TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    // and TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 will not respond to server-hello
    // if the certificate is generated with below extensions.
    // Firefox works fine with them.
	/* Add various extensions: standard extensions - RFC-5280 */
	add_ext(info->x509, NID_basic_constraints, "critical,CA:TRUE");
	add_ext(info->x509, NID_key_usage, "critical,keyCertSign,cRLSign");
	add_ext(info->x509, NID_subject_key_identifier, "hash");
#endif
	rc = X509_sign(info->x509, info->pkey, info->digest);
	
	return (rc);
error:
    LOGV("[%s:%u] error\n", __func__, __LINE__);
	return(0);
}

// generate certificate fingerprint per rfc4572
// return string size (excluding trailing null)
static int calc_certificate_digest(X509 *x, char *text, int size)
{
/*
    const X509_ALGOR  *sig_algo = X509_get0_tbs_sigalg(x);
    const ASN1_OBJECT *algo_obj=0;
    int z=0;
    const void *p=0;
    X509_ALGOR_get0(&algo_obj, &z, &p, sig_algo);
    printf("[%s:%u] algo_obj=%p x=%d p=%p\n", __func__, __LINE__, algo_obj, z, p);
    // e.g. algo_obj name=sha256WithRSAEncryption nid=668
    const EVP_MD *hash_type = EVP_get_digestbyobj(algo_obj);
    printf("[%s:%u] hash_type=%p\n", __func__, __LINE__, hash_type);
    int hash_nid = EVP_MD_type(hash_type);
*/
    int hash_nid=0;
    // openssl 1.1.1
    X509_get_signature_info(x, &hash_nid, 0, 0, 0);
    const ASN1_OBJECT *hash_obj = OBJ_nid2obj(hash_nid);
    char *hash_func=0;
    // match to "Hash Function Name" in rfc4572 section 8.0
    if( hash_obj == OBJ_txt2obj("1.2.840.113549.2.2", 1) )
    {
        hash_func = "md2";
    }
    else if( hash_obj == OBJ_txt2obj("1.2.840.113549.2.5", 1) )
    {
        hash_func = "md5";
    }
    else if( hash_obj == OBJ_txt2obj("1.3.14.3.2.26", 1) )
    {
        hash_func = "sha-1";
    }
    else if( hash_obj == OBJ_txt2obj("2.16.840.1.101.3.4.2.4", 1) )
    {
        hash_func = "sha-224";
    }
    else if( hash_obj == OBJ_txt2obj("2.16.840.1.101.3.4.2.1", 1) )
    {
        hash_func = "sha-256";

    }
    else if( hash_obj == OBJ_txt2obj("2.16.840.1.101.3.4.2.2", 1) )
    {
        hash_func = "sha-384";
    }
    else if( hash_obj == OBJ_txt2obj("2.16.840.1.101.3.4.2.3", 1) )
    {
        hash_func = "sha-512";
    }

    uint8_t  md[EVP_MAX_MD_SIZE]={(0)};
    unsigned int mn = sizeof(md);
    const EVP_MD *hash_type = EVP_get_digestbynid(hash_nid);
    X509_digest(x, hash_type, md, &mn);
    // @len includes trailing null
    int len = strlen("fingerprint:") + strlen(hash_func) + 3 * mn;

    if( text && (size >= len) )
    {
        int j, k = 0;
        
        k += sprintf(text + k, "fingerprint:%s ", hash_func);

        for(j = 0; j < mn - 1; j++)
        {
            k += sprintf(text + k, "%.2X:", md[j]);
        }
        k += sprintf(text + k, "%.2X", md[j]);
    }
    
    return len;
}

////////////////////////////////////////////////////////////////////////////////

#define X509_CTX_SIZE  4096

typedef struct x509_ctx_t
{
	void   * certificate;
	void   * private_key;
	char   * fingerprint;  // of certificate

    const EVP_MD * digest_type;  // sha256, etc

	// space management
    int      pnt;
    int      max;
    uint8_t  buf[0];

}  x509_ctx_t;

static int  load_x509_context(FILE *fc, x509_ctx_t *x509_ctx)
{
	X509 *x509 = PEM_read_X509(fc, 0, 0, 0);
	
	if( x509 == 0) return 0; // invalid x509 file

    fseek(fc, 0, SEEK_SET);
    
    EVP_PKEY *key = PEM_read_PrivateKey(fc, 0, 0, 0);
    
    if( key == 0 ) 
    {
		X509_free(x509);
		
		return 0;
	}

    if( x509_ctx )
    {
        x509_ctx->certificate = x509;
        x509_ctx->private_key = key;
        int hash_nid=0;
        // openssl 1.1.1
        X509_get_signature_info(x509, &hash_nid, 0, 0, 0);
        x509_ctx->digest_type = EVP_get_digestbynid(hash_nid);
	}
	
	return 1;
}

static int  make_x509_context(int key_algo, x509_ctx_t *x509_ctx)
{
    cert_info_t  *info= __builtin_alloca(sizeof(cert_info_t));
    __builtin_memset(info, 0, sizeof(cert_info_t));
    
    info->key_algo = key_algo;
    
    switch(info->key_algo )
    {
	case e_key_algo_rsa:
	case e_key_algo_dsa:
        info->key_bits = 512;
        break;
    case e_key_algo_ec:
        info->key_bits = 128;
        break;
    default:
        break;
    }
    info->serial = 1;
    info->days = 365; // iceagent checks expiration. be sure to be consistent
    
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

	int rc = make_certificate(info);
	
	if( rc > 0 && x509_ctx )
	{
        x509_ctx->certificate = info->x509;
        x509_ctx->private_key = info->pkey;
        x509_ctx->digest_type = info->digest;
	}
	
	return rc;
}

//
// load certificate and privare key; calculate certificate fingerprint
//
void * init_x509_context(const char *cert_file)
{
	int rc = 0;
	x509_ctx_t ctx={(0)};
	FILE *fc = fopen(cert_file, "rb");
	if( fc )
	{
		rc = load_x509_context(fc, &ctx);
		fclose(fc);
	}
    if( rc <= 0 )
    {
        //rc = make_x509_context(e_key_algo_rsa, &ctx);
        rc = make_x509_context(e_key_algo_ec, &ctx);
    }
    if( fc == 0 && rc > 0 )
    {
        fc = fopen(cert_file, "wb");
        if( fc )
        {
			PEM_write_X509(fc, ctx.certificate);
			PEM_write_PrivateKey(fc, ctx.private_key, 0,0,0,0,0);
			fclose(fc);
		}
		else
		{
			rc = 0; // error file open for write
		}
    }
    
    if( rc <= 0 ) return 0;
    
    x509_ctx_t * x509_ctx = malloc(X509_CTX_SIZE);
	*(x509_ctx) = ctx;
    x509_ctx->max = X509_CTX_SIZE - sizeof(x509_ctx_t);

    // calculate certificate fingerprint
    x509_ctx->fingerprint = (char*)(x509_ctx->buf + x509_ctx->pnt);

    int n = calc_certificate_digest(x509_ctx->certificate,
                x509_ctx->fingerprint, x509_ctx->max);

    x509_ctx->pnt += (n+1);

    return x509_ctx;
}

void * free_x509_context(void *x509_ctx)
{
	x509_ctx_t * ctx = x509_ctx;
	
	if( ctx == 0 )  return 0;
	
	if( ctx->certificate )
	{
		X509_free(ctx->certificate);
	}
	if( ctx->private_key )
	{
	    EVP_PKEY_free(ctx->private_key);
	}
	free(ctx);
	return 0;
}

int    get_x509_fingerprint(void *x509_ctx, char *text, int size)
{
	x509_ctx_t * ctx = x509_ctx;

	int len = strlen(ctx->fingerprint);

	if( size > len) strcpy(text, ctx->fingerprint);

	return len;
}

int    der_x509_certificate(void *x509_ctx, unsigned char *der, int size)
{
	x509_ctx_t * ctx = x509_ctx;

    // internal to DER
    int len = i2d_X509(ctx->certificate, NULL);

    if( len <= size && der )
    {
        unsigned char *out = der;
        // ! callee changes @out value
        i2d_X509(ctx->certificate, &out);
    }

    return len;
}

////////////////////////////////////////////////////////////////////////////////

int    hash_sha256_array(unsigned char *md, unsigned char *in, int len)
{
    if( in && len >= 0 ) SHA256(in, len, md);

    return SHA256_DIGEST_LENGTH;
}

// hash input vector with sha256
int    hash_sha256_iovec(unsigned char *out, struct iovec *in)
{
    int e, j;
    unsigned char md[SHA256_DIGEST_LENGTH];

    SHA256_CTX sha2={(0)};

    e = SHA256_Init(&sha2);
    if( e != 1 ) return 0; // error

    for(j=0; in[j].iov_base && in[j].iov_len >= 0; j++)
    {
        e = SHA256_Update(&sha2, in[j].iov_base, in[j].iov_len);
        if( e != 1 ) break;
    }
    if( e == 1 ) e = SHA256_Final(md, &sha2);
    if( e != 1 ) return 0; // error

    // sign the hash result

    if( out )
    {
        memcpy(out, md, SHA256_DIGEST_LENGTH);
    }
    return SHA256_DIGEST_LENGTH; // 32
}

//
// digitally sign a block of data with rsa_pkcs1_sha256
// iovec array @in must be terminated with an invalid element
//
// while not explicitly limited to rsa_pkcs1_sha256 certificate,
// it is assumed that certificate is created with rsa and sha256
// call to EVP_DigestSignInit() has limit on digest types
//
int sign_with_x509(void *x509_ctx,
                   unsigned char *ds_out, int ds_len, struct iovec *in)
{
    int e, j;
    size_t sign_len=0;
	x509_ctx_t * ctx = x509_ctx;

    EVP_MD_CTX *mdctx = 0;

    if(!(mdctx = EVP_MD_CTX_create()))
    {
        LOGV("[%s:%u] PANIC!\n", __func__, __LINE__);
        goto exit;
    }
    if( ctx->digest_type == 0 )
    {
        LOGV("[%s:%u] PANIC: null digest type\n", __func__, __LINE__);
        goto exit;
    }
    // at least for RSA, EVP_MD type is redundant
    e = EVP_DigestSignInit(mdctx, 0, /*ctx->digest_type*/0, 0, ctx->private_key);
    if( e != 1 )
    {
        LOGV("[%s:%u] PANIC!\n", __func__, __LINE__);
        goto exit;
    }

    for(j=0; in[j].iov_base && in[j].iov_len >= 0; j++)
    {
        e = EVP_DigestSignUpdate(mdctx, in[j].iov_base, in[j].iov_len);

        if( e != 1 ) break;
    }
    if( e != 1 )
    {
        LOGV("[%s:%u] PANIC!\n", __func__, __LINE__);
        goto exit;
    }
    e = EVP_DigestSignFinal(mdctx, 0, &sign_len);
    if( e != 1 )
    {
        LOGV("[%s:%u] PANIC!\n", __func__, __LINE__);
        goto exit;
    }
    if( (int)sign_len <= ds_len && ds_out )
    {
        e = EVP_DigestSignFinal(mdctx, ds_out, &sign_len);
    }
//LOGV("[%s:%u] sign_len=%ld\n", __func__, __LINE__, sign_len);
    if( e != 1 )
    {
        LOGV("[%s:%u] PANIC!\n", __func__, __LINE__);
        goto exit;
    }
exit:

    if(mdctx) EVP_MD_CTX_destroy(mdctx);

    return (int)sign_len;
}

//
// @cert_ptr as serialized x509 certificate in DER
//
int  verify_signature(void *cert_ptr, int cert_len,
                      void *sign_ptr, int sign_len,
                      void *text_ptr, int text_len)
{
    int e = 0;
    EVP_MD_CTX *mdctx = 0;
    EVP_PKEY   *pkey = 0;

    const unsigned char *der = cert_ptr;

    // DER to internal - ! callee alters @der value
    X509 *x509 = d2i_X509(NULL, &der, cert_len);

    if( x509 == 0 )
    {
        LOGV("[%s:%u] PANIC\n", __func__, __LINE__);
        goto exit;
    }
    // extract publick key from certificate
    pkey = X509_get0_pubkey(x509);

    if( pkey == 0 )
    {
        LOGV("[%s:%u] PANIC\n", __func__, __LINE__);
        goto exit;
    }

    if(!(mdctx = EVP_MD_CTX_create()))
    {
        LOGV("[%s:%u] PANIC!\n", __func__, __LINE__);
        goto exit;
    }
    // at least for RSA, EVP_MD type is redundant
    e = EVP_DigestVerifyInit(mdctx, 0, 0/*EVP_sha256()*/, 0, pkey);
    if( e != 1 )
    {
        LOGV("[%s:%u] PANIC\n", __func__, __LINE__);
        goto exit;
    }
    e = EVP_DigestVerifyUpdate(mdctx, text_ptr, text_len);
    if( e != 1 )
    {
        LOGV("[%s:%u] PANIC\n", __func__, __LINE__);
        goto exit;
    }
    e = EVP_DigestVerifyFinal(mdctx, sign_ptr, sign_len);

exit:

    if( mdctx ) EVP_MD_CTX_destroy(mdctx);

    if( x509 ) X509_free(x509);

    return e;  // boolean true if verified true
}

////////////////////////////////////////////////////////////////////////////////

#ifdef LOCAL_BUILD

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
    void *x509_ctx = init_x509_context("cert.pem");

    if( x509_ctx )
    {
		x509_ctx_t * ctx = x509_ctx;
		X509_print_fp(stdout, ctx->certificate);
		PEM_write_PrivateKey(stdout, ctx->private_key, 0,0,0,0,0);
		printf("%s\n", ctx->fingerprint);
	}
#ifdef TEST_SHA256
    unsigned char md[SHA256_DIGEST_LENGTH];
    struct iovec ina[2]={(0)};
    ina[0].iov_base="abc";
    ina[0].iov_len = 3;
    int e=0;
    e = hash_sha256_iovec(md, ina);
    LOGV("[%s:%u] hash_sha256_iovec size=%d\n", __func__, __LINE__, e);
    dump_hex(md, SHA256_DIGEST_LENGTH);
    e = hash_sha256_array(md, (unsigned char*)"abc", 3);
    LOGV("[%s:%u] hash_sha256_array size=%d\n", __func__, __LINE__, e);
    dump_hex(md, SHA256_DIGEST_LENGTH);
    char *ok="ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad";
    printf("must be\n%s\n", ok);
#endif // TEST_SHA256

#ifdef TEST_SIGNATURE
    // test vector sha256
    struct iovec inb[2]={(0)};
    inb[0].iov_base="abc";
    inb[0].iov_len = 3;
    unsigned char sign[256];

    int n = sign_with_x509(x509_ctx, sign, sizeof(sign), inb);

    LOGV("[%s:%u] text=%s signature size=%d\n",
        __func__, __LINE__, (char*)in[0].iov_base, n);

    if(n > 0 ) dump_hex(sign, n);

    // verify signature
    unsigned char der[1<<10];
    int len = der_x509_certificate(x509_ctx, der, sizeof(der));

    int e = verify_signature(der, len, sign, n, "abc", 3);

    LOGV("[%s:%u] signature verification=%d\n", __func__, __LINE__, e);
#endif  // TEST_SIGNATURE
    if( x509_ctx )
    {
		free_x509_context(x509_ctx);
    }

    return 0;
}
#endif
