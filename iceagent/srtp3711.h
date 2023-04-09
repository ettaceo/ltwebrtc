// file srtp3711.h
// date : 04/18/2020 historic
#ifndef SRTP3711_H_
#define SRTP3711_H_

typedef unsigned char u8_t;
typedef unsigned short u16_t;
typedef unsigned int u32_t;

#ifdef __cplusplus
extern "C" {
#endif

void * init_srtp_crypt(u8_t *master_key, int key_length, u8_t *master_salt);
void * free_srtp_crypt(void *crypx);
int    encrypt_rtp_128(void *crypx, u8_t *rtp, u32_t length, u8_t *out);
int    decrypt_rtp_128(void *crypx, u8_t *rtp, u32_t length, u8_t *out);
int    encrypt_rtcp_128(void *crypx, u8_t *rtcp, u32_t length, u8_t *out);
int    decrypt_rtcp_128(void *crypx, u8_t *rtcp, u32_t length, u8_t *out);

u32_t  encrypt_get_index(void *crypx);
void   encrypt_set_index(void *crypx, u32_t index);

#ifdef __cplusplus
}
#endif

#endif // SRTP3711_H_

