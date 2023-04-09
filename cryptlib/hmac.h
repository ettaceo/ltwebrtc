#ifndef HMAC_MD5_H_
#define HMAC_MD5_H_
#include <string.h>
#define bzero(p, n) memset((p), 0, (n))
#define bcopy(s, d, n) memcpy((d), (s), (n))

#define HMAC_MD5(key, key_len, data, data_len, result) \
    hmac_md5(data, data_len, key, key_len, result)

#define HMAC_SHA1(key, key_len, data, data_len, result) \
    hmac_sha1(data, data_len, key, key_len, result)

#ifdef __cplusplus
extern "C" {
#endif

void hmac_md5(unsigned char* text, int text_len, 
              unsigned char* key, int key_len, unsigned char digest[16]);

void hmac_sha1(unsigned char* text, int text_len,
               unsigned char* key, int key_len, unsigned char digest[20]);

#ifdef __cplusplus
}
#endif

#endif // HMAC_MD5_H_
