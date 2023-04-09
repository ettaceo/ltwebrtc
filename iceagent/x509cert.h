// file : x509cert.h
// date : 01/29/2020
#ifndef X509CERT_H_
#define X509CERT_H_
#include <stdint.h>
#include <sys/uio.h>  // struct iovec

// openssl
#ifndef SHA256_DIGEST_LENGTH
    #define SHA256_DIGEST_LENGTH 32
#endif

#ifdef __cplusplus
#extern "C" {
#endif

void * init_x509_context(const char *cert_file);

void * free_x509_context(void *x509_ctx);

int    get_x509_fingerprint(void *x509_ctx, char *text, int size);

int    der_x509_certificate(void *x509_ctx, unsigned char *der, int size);

int    sign_with_x509(void *x509_ctx,
                      unsigned char *ds_out, int ds_len, struct iovec *in);

int    hash_sha256_array(unsigned char *md, unsigned char *in, int len);
int    hash_sha256_iovec(unsigned char *md, struct iovec *in);

#ifdef __cplusplus
}
#endif

#endif  // X509CERT_H_
