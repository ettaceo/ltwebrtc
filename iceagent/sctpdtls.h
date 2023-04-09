// file : sctpdtls.h
// date : 05/0/2020
#ifndef SCTPDTLS_H_
#define SCTPDTLS_H_

#ifdef __cplusplus
extern "C" {
#endif

void  sctp_init(void);

void  sctp_exit(void);

int   sctp_rx(void *dtls_ctx, void *data, int size);

void  sctp_halt(void *dtls_ctx);

void *dtls_get_sctp(void *dtls_ctx);

void  dtls_set_sctp(void *dtls_ctx, void *sctp_tcb);

int   dtls_tx_userdata(void *ctx, void *data, int size);

void *dtls_ice_session(void *ctx);

#ifdef __cplusplus
}
#endif

#endif // SCTPDTLS_H_
