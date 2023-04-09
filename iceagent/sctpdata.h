// file : sctpdata.h
// date : 05/17/2020
#ifndef SCTPDATA_H_
#define SCTPDATA_H_

#define SCTP_RX_STREAMS   16
#define SCTP_TX_STREAMS   16
#define MAX_DATA_STREAMS  16
#define MAX_DATA_CHHANELS  4

// draft-ietf-rtcweb-data-protocol-09.pdf
// draft sec 6.: stream id to be odd numbers from dtls server side
#define WEBRTC_STREAM_ID  1

#define MAX_LABEL_LENGTH   122

typedef struct bufx_t
{
    int  max;
    int  pnt;
    unsigned char buf[0];

}   bufx_t;

// rfc4960 section 3.3.1.
typedef struct data_hdr_t
{
    unsigned short stream_id;
    unsigned short stream_seq;
    unsigned int   ppid;       // protocol id
    unsigned char  data[0];

}   data_hdr_t;

#ifdef __cplusplus
extern "C" {
#endif

void  data_init(int count, int *ports);

// draft sec 6.: stream id to be odd numbers from dtls server side
void *data_open(void *tcb, int stream_id, int dst_port, int src_port);

void  data_halt(void *ctx);

int   data_recv(void *data_ctx, void *data_hdr, int data_len);

int   webrtc_send(void *ctx, int stream_id, const void *msg, int length);

#ifdef __cplusplus
}
#endif

#endif // SCTPDATA_H_

