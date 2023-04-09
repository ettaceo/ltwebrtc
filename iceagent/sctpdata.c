// file : sctpdata.c
// date : 05/17/2020
// implement rtcweb data protocol
// https://tools.ietf.org/pdf/draft-ietf-rtcweb-data-protocol-09.pdf
//
#include <stdio.h>
#include <errno.h>

#include "sctpdata.h"
#include "sctp4960.h"
#include "mediartp.h"

//#define LOGV(...)
#define LOGV printf
#define LOGI printf

// ppid
enum {
    e_webrtc_dcep=50,   // draft-ietf-rtcweb-data-protocol-09.txt
    e_webrtc_string=51, // draft-ietf-rtcweb-data-channel-13.txt
    e_webrtc_binary_partial=52, // deprecated
    e_webrtc_binary=53,
    e_webrtc_string_partial=54, // deprecated
    e_webrtc_string_empty=56,
    e_webrtc_binary_empty=57,
    e_ppid_max
};

// e_webrtc_dcep message type draft-ietf-rtcweb-data-protocol-09.txt
enum {
    e_webrtc_data_channel_ack=2,
    e_webrtc_data_channel_open=3,
    e_webrtc_max
};

// channel type - draft-ietf-rtcweb-data-protocol-09.txt
enum {
    e_DATA_CHANNEL_RELIABLE=0x00,
    e_DATA_CHANNEL_RELIABLE_UNORDERED=0x80,
    e_DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT=0x01,
    e_DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT_UNORDERED=0x81,
    e_DATA_CHANNEL_PARTIAL_RELIABLE_TIMED=0x02,
    e_DATA_CHANNEL_PARTIAL_RELIABLE_TIMED_UNORDERED=0x82,
    e_DATA_CHANNEL_type_max
};

struct channel_open
{
    unsigned char message_type;
    unsigned char channel_type;
    unsigned short priority;
    unsigned int reliability_parameters;
    unsigned short label_length;
    unsigned short protocl_length;
    // label
    unsigned char label_string[0];
    // protocol data
};

// rfc4960 3.3.1. Payload Data after TSN
// number of streams as indicated in INIT and INIT-ACK
struct data_ctx_t
{
    void  *tcb;
    int    self_port;
    int    peer_port;

    struct {
        int            is_active;
        unsigned short rx_stream_seq;
        unsigned short tx_stream_seq;
        char           chnl_label[MAX_LABEL_LENGTH];

        data_hdr_t     tx_header;

    }  stream[MAX_DATA_STREAMS];

}  g_data_ctx[MAX_DATA_CHHANELS];


static int  g_port_count;
static int  g_open_ports[64];

////////////////////////////////////////////////////////////////////////////////

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

static void set_tx_header(struct data_ctx_t *data_ctx, int stream_id, int ppid)
{
    data_hdr_t *hdr = &(data_ctx->stream[stream_id].tx_header);

    __builtin_memset(hdr, 0, sizeof(*hdr));

    hdr->stream_id = htons(stream_id);
    hdr->stream_seq = htons(data_ctx->stream[stream_id].tx_stream_seq);
    hdr->ppid = htonl(ppid);

    data_ctx->stream[stream_id].tx_stream_seq += 1;
}

static int data_send(void *data_ctx, int sid, const void *msg, int len)
{
    struct data_ctx_t *ctx = data_ctx;

    unsigned char *buf =__builtin_alloca(sizeof(data_hdr_t)+len);

    __builtin_memcpy(buf, &ctx->stream[sid].tx_header, sizeof(data_hdr_t));

    __builtin_memcpy(buf + sizeof(data_hdr_t), msg, len);
    
    sctp_send_out(ctx->tcb, buf, sizeof(data_hdr_t) + len);

    return (int)sizeof(data_hdr_t) + len;
}

// assuming string paylaod
int webrtc_send(void *ctx, int stream_id, const void *msg, int length)
{
    int ppid = (length == 0 ? e_webrtc_string_empty : e_webrtc_string);
    set_tx_header(ctx, stream_id, ppid);
    data_send(ctx, stream_id, msg, length);
    return length;
}

// draft-ietf-rtcweb-data-protocol-09.txt
static int webrtc_dcep(struct data_ctx_t *data_ctx, data_hdr_t *hdr, int len)
{
    int  idx = ntohs(hdr->stream_id);
    int  seq = ntohs(hdr->stream_seq);

//    LOGV("[%s:%u] stream_id=%d seq=%d len=%d\n", __func__, __LINE__, idx, seq, len);

    struct channel_open *msg = (void*)hdr->data;
    
    switch( msg->message_type )
    {
    case e_webrtc_data_channel_open:
        LOGV("[%s:%u] e_webrtc_data_channel_open(id=%d) %.*s channel type:%.2x\n",
            __func__, __LINE__,
            idx, ntohs(msg->label_length), msg->label_string, msg->channel_type);
        data_ctx->stream[idx].rx_stream_seq = seq;
        data_ctx->stream[idx].tx_stream_seq = 0;
        data_ctx->stream[idx].is_active = 1; // boolean
        {
            __builtin_memset(data_ctx->stream[idx].chnl_label, 0, MAX_LABEL_LENGTH);
            int label_length = ntohs(msg->label_length);
            if( label_length > 0 )
            {
                __builtin_memcpy(data_ctx->stream[idx].chnl_label,
                                 msg->label_string, MAX_LABEL_LENGTH);
            }
        }
        // send ack to open
        set_tx_header(data_ctx, ntohs(hdr->stream_id), e_webrtc_dcep);
        unsigned char ack = e_webrtc_data_channel_ack;
        data_send(data_ctx, idx, &ack, sizeof(ack)); // DATA_CHANNEL_ACK
        break;
    case e_webrtc_data_channel_ack:
        LOGV("[%s:%u] e_webrtc_data_channel_ack(id=%d)\n", __func__, __LINE__, idx);
        break;
    default:
        LOGV("[%s:%u] UNKNOWN message type\n", __func__, __LINE__);
        break;
    }

    return 0;
}

//
// draft-ietf-rtcweb-data-protocol-09.txt
//
int   data_recv(void *data_ctx, void *data_hdr, int data_len)
{
    data_hdr_t *hdr = data_hdr;

    LOGV("[%s:%u] stream_id=%d stream_seq=%d\n", __func__, __LINE__,
        ntohs(hdr->stream_id), ntohs(hdr->stream_seq));
    
    int ppid = ntohl(hdr->ppid);
    
    switch( ppid )
    {
    case e_webrtc_dcep:
        LOGV("[%s:%u] e_webrtc_dcep len=%d\n", __func__, __LINE__, data_len);
        webrtc_dcep(data_ctx, data_hdr, data_len);
        break;
    case e_webrtc_string:
        break;
    case e_webrtc_binary:
        LOGV("[%s:%u] binary length=%d\n", __func__, __LINE__,
            (int)(data_len - sizeof(*hdr)));
        dump_hex(data_ctx, data_len - sizeof(*hdr));
        break;
    default:
        LOGI("[%s:%u] unknown length=%d\n", __func__, __LINE__,
            (int)(data_len - sizeof(*hdr)));
        break;
    }

    return 0;
}

//
// open data channel - draft-ietf-rtcweb-data-protocol-09.txt
//
void * data_open(void *tcb, int stream_id, int dst_port, int src_port)
{
    int i;

    struct data_ctx_t *ctx;

    for(i = 0, ctx = g_data_ctx + 0; i < MAX_DATA_CHHANELS; i++, ctx++)
    {
        if( ctx->tcb == 0 ) break;  // valid @sock is positive
    }
    if( i == MAX_DATA_CHHANELS )
    {
        LOGV("[%s:%u] WARNING: no more channel available\n", __func__, __LINE__);
        return 0;
    }

    ctx->tcb = tcb;
    ctx->self_port = dst_port;
    ctx->peer_port = src_port;

    struct channel_open *msg = __builtin_alloca(sizeof(*msg));

    // draft sec 6.: stream id to be odd numbers from dtls server side
    set_tx_header(ctx, stream_id, e_webrtc_dcep);

    __builtin_memset(msg, 0, sizeof(*msg));

    msg->message_type = e_webrtc_data_channel_open;
    msg->channel_type = e_DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT_UNORDERED,
    msg->priority = 0;
    msg->reliability_parameters = 0; // 0 retransmissions

    data_send(ctx, stream_id, msg, sizeof(*msg));

    return ctx;
}

void  data_halt(void *ctx)
{
    if( ctx )
    {
        struct data_ctx_t *data_ctx = ctx;
LOGV("[%s:%u] reset data_ctx\n", __func__, __LINE__);
        // clean up
        __builtin_memset(data_ctx, 0, sizeof(*data_ctx));
    }
}

// [05/23/2020] not really in use
void  data_init(int count, int *ports)
{
    if( count > 0 && ports)
    {
        if( count > sizeof(g_open_ports)/sizeof(g_open_ports[0]) )
        {
            count = sizeof(g_open_ports)/sizeof(g_open_ports[0]);
        }
        g_port_count = count;

        __builtin_memcpy(g_open_ports, ports, count*sizeof(g_open_ports[0]));
    }
}
