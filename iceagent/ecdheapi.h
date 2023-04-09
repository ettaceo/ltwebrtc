// file : ecdheapi.h
// date : 04/05/2020
#ifndef ECDHEAPI_H_
#define ECDHEAPI_H_

#ifdef __cplusplus
extern "C" {
#endif

void * init_ec_keypair(void);
void   exit_ec_keypair(void *ctx);
int    copy_ec_pub_key(void *ctx, unsigned char *buf, int len);
int    get_curved_name(void *ctx);
int    calc_pre_master(void *ctx, unsigned char *pubk, int klen,
                       unsigned char *secret);

#ifdef __cplusplus
}
#endif

#endif // ECDHEAPI_H_

