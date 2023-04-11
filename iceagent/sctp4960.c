// file : sctp4960.c
// date : 05/07/2020
#include <pthread.h>
#include <errno.h>
#include <stdio.h>

#include "cryptlib/prng.h"
#include "cryptlib/hmac.h"
#include "sctp4960.h"
#include "sctpdtls.h"
#include "sctpdata.h"

#define LOGV(...)
#define LOGI printf

#define SCTP_SOCKET_MAX  8

enum {
    e_state_null,
    e_state_taken,
    e_state_bound,
    e_state_accepting,
    e_state_connected,
    e_state_shutdown,
    e_state_max
};

#define SCTP_RX_BUF_MAX  (1<<20)
#define SCTP_TX_BUF_MAX  (1<<20)

typedef struct sctp_tcb_t
{
    int    state;

    void  *dtls_ctx;
    void  *data_ctx;   // sctp data context

    stcpaddr_t  peer_addr;
    stcpaddr_t  self_addr;

    unsigned int rx_tag;    // endian-less
    unsigned int tx_tag;    // endian-less

    unsigned int peer_wnd;  // max send
    unsigned int self_wnd;  // max receive

    unsigned int rx_tsn;
    unsigned int tx_tsn;
    unsigned int tx_ack; // acked tsn

    unsigned int recnf_sn;  // re-configure request sequence number rfc6525

    unsigned short rx_streams;
    unsigned short tx_streams;

    pthread_mutex_t lock;
    pthread_cond_t  cond;

    pthread_mutex_t write_lock[1];
    pthread_cond_t  write_cond[1];

    bufx_t  *rx_buf;
    bufx_t  *tx_buf;
    
}   sctp_tcb_t;

static sctp_tcb_t g_sctp_tcb[SCTP_SOCKET_MAX];

static pthread_mutex_t  sctp_lock=PTHREAD_MUTEX_INITIALIZER;

#define HMAC_KEY_LEN 32
static unsigned char hmac_key[HMAC_KEY_LEN];
#define DUMP_HEX
////////////////////////////////////////////////////////////////////////////////
#ifdef DUMP_HEX
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
#endif
////////////////////////////////////////////////////////////////////////////////

#define ACQUIRE_TX_LOCK(tcb) pthread_mutex_lock(&((sctp_tcb_t*)tcb)->lock)
#define RELEASE_TX_LOCK(tcb) pthread_mutex_unlock(&((sctp_tcb_t*)tcb)->lock)

// clear buffers
static void sctp_reuse_tcb(sctp_tcb_t *tcb)
{
    tcb->state = e_state_null;

    tcb->dtls_ctx = 0;
    tcb->data_ctx = 0;

    __builtin_memset(&(tcb->peer_addr), 0, sizeof(stcpaddr_t));
    __builtin_memset(&(tcb->self_addr), 0, sizeof(stcpaddr_t));

    tcb->rx_tag = 0;
    tcb->tx_tag = 0;

    tcb->self_wnd = SCTP_RX_BUF_MAX;
    tcb->peer_wnd = 0;
    tcb->rx_tsn = 0;
    tcb->tx_tsn = 0;

    tcb->rx_streams = SCTP_RX_STREAMS;
    tcb->tx_streams = SCTP_TX_STREAMS;

    tcb->rx_buf->pnt = 0;
    tcb->tx_buf->pnt = 0;
}

////////////////////////////////////////////////////////////////////////////////

static void *bufx_alloc(unsigned int max)
{
    bufx_t *x = __builtin_malloc(sizeof(bufx_t)+max);
    x->max = max;
    x->pnt = 0;
    
    return x;
}

// call once at program startup
void  sctp_init(void)
{
    int j=0;
LOGV("[%s:%u] SCTP_SOCKET_MAX=%d\n", __func__, __LINE__, SCTP_SOCKET_MAX);
    pthread_mutex_lock(&sctp_lock);

    for(j= 0; j < SCTP_SOCKET_MAX; j++)
    {
        sctp_tcb_t *tcb = g_sctp_tcb + j;

        if( tcb->state == e_state_null )
        {
            tcb->rx_buf = bufx_alloc(SCTP_RX_BUF_MAX);
            tcb->tx_buf = bufx_alloc(SCTP_TX_BUF_MAX);
            pthread_mutexattr_t attr;
            pthread_mutexattr_init(&attr);
            pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
            pthread_mutex_init(&(tcb->lock), &attr);
            pthread_cond_init(&(tcb->cond), 0);
            pthread_mutex_init(tcb->write_lock, &attr);
            pthread_cond_init(tcb->write_cond, 0);
        }
    }

    // generate hmac-sha1 key
    // HMAC_KEY_LEN must be multiple of 8
    for(j = 0; j < HMAC_KEY_LEN; j+=8)
    {
        *(unsigned long long*)(hmac_key+j) = randk();
    }

    pthread_mutex_unlock(&sctp_lock);

    // initialize data protocol layer    
    data_init(0, 0);
}

// called at program shutdown
void  sctp_exit(void)
{
    int j=0;

    pthread_mutex_lock(&sctp_lock);

    for(j= 0; j < SCTP_SOCKET_MAX; j++)
    {
        sctp_tcb_t *tcb = g_sctp_tcb + j;
        
        if( tcb->state == e_state_null )
        {
            if( tcb->rx_buf ) __builtin_free(tcb->rx_buf);
            if( tcb->tx_buf ) __builtin_free(tcb->tx_buf);
            pthread_cond_destroy(&(tcb->cond));
            pthread_mutex_destroy(&(tcb->lock));
        }
    }

    pthread_mutex_unlock(&sctp_lock);
LOGV("[%s:%u] done\n", __func__, __LINE__);
}

// https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml
static unsigned short stcp_options[]=
{
    0xc000,  // rfc3758
    0x8008,  // rfc5061
    0x8002,  // rfc4895
    0x8004,  // rfc4895
    0x8003,  // rfc4895
};
#define SCTP_OPTIONS_LEN (sizeof(stcp_options)/sizeof(stcp_options[0]))

extern unsigned int generate_crc32c(unsigned char *, int);

// rfc4960 section 6.8, appendix B.
static int  sctp_test_crc32c(sctp_common_t *hdr, int size)
{
    unsigned int csum = hdr->checksum;
    hdr->checksum = 0;
    
    unsigned int isum = generate_crc32c((void*)hdr, size);

    //LOGV("[%s:%u] csum=%.8X isum=%.8X\n", __func__, __LINE__, csum, isum);

    // recover
    hdr->checksum = csum;
    
    return (ntohl(csum) - isum);
}

// rfc4960 section 6.8, appendix B.
static int  sctp_make_crc32c(sctp_common_t *hdr, int size)
{
    hdr->checksum = 0;
    
    unsigned int isum = generate_crc32c((void*)hdr, size);

    hdr->checksum = htonl(isum);

    return (isum);
}

void * tcb_ice_session(void *tcb)
{
    void *ice_session = 0;
    if( tcb && ((sctp_tcb_t*)tcb)->dtls_ctx )
    {
        ice_session = dtls_ice_session(((sctp_tcb_t*)tcb)->dtls_ctx);
    }
    return ice_session;
}

static void * sctp_fetch_tcb(void *dtls_ctx, sctp_common_t *hdr, int size)
{
    sctp_tcb_t *tcb = 0;
    
    int j;
    // search for exact dtls_ctx match - this is not necessary as
    // dtls_get_sctp(dlts_ctx) should have been called in advance
    for(j= 0; j < SCTP_SOCKET_MAX; j++, tcb = 0)
    {
        tcb = g_sctp_tcb + j;

        if( tcb->dtls_ctx == dtls_ctx ) break;
    }
    if( tcb == 0 )
    {
        // if sctp_bind() is called, match the port 
        // if there is not previous dtls_ctx linking
        for(j= 0; j < SCTP_SOCKET_MAX; j++, tcb = 0)
        {
            tcb = g_sctp_tcb + j;

            if( tcb->self_addr.sin_port == hdr->destination_port &&
                tcb->state != e_state_null && tcb->dtls_ctx ==0 ) break;
        }
    }
    if( tcb == 0 )
    {
        // assign an unused tcb and set state
        for(j= 0; j < SCTP_SOCKET_MAX; j++, tcb = 0)
        {
            tcb = g_sctp_tcb + j;

            if( tcb->state == e_state_null )
            {
                sctp_reuse_tcb(tcb);
                tcb->state = e_state_accepting;
                tcb->self_addr.sin_port = hdr->destination_port;
                break;
            }
        }
    }
    if( tcb )
    {
        // check rx verification tag
        if( hdr->verification_tag != tcb->tx_tag )
        {
            LOGV("[%s:%u] vtag mismatch(%.8x %.8x)\n", __func__, __LINE__,
                hdr->verification_tag, tcb->tx_tag);

            tcb = 0;
        }
    }

    return tcb;
}

// return common header size
static int sctp_set_header(sctp_tcb_t *tcb, sctp_common_t *hdr)
{
    hdr->source_port = tcb->self_addr.sin_port;  // network order
    hdr->destination_port = tcb->peer_addr.sin_port;
    hdr->verification_tag = tcb->tx_tag;  // endian-less
    hdr->checksum = 0;

    return sizeof(*hdr);
}

// forward tsn - rfc3758
static int sctp_make_ftsn(sctp_tcb_t *tcb, unsigned int tsn)
{
LOGI("[%s:%u] FORWARD TSN %u\n", __func__, __LINE__, tsn);
    ACQUIRE_TX_LOCK(tcb);

    if( tcb->tx_buf->pnt == 0 )
    {
        tcb->tx_buf->pnt = sctp_set_header(tcb, (void*)tcb->tx_buf->buf);
    }
    // append chunk
    sctp_chunk_t *chunk = (void*)(tcb->tx_buf->buf + tcb->tx_buf->pnt);

    memset(chunk, 0, sizeof(sctp_chunk_t));

    chunk->type = e_type_forward_tsn;
    chunk->length = htons(8);
    *(unsigned int*)(chunk->value) = htonl(tsn);

    tcb->tx_buf->pnt += ntohs(chunk->length);

    // padding
    while(tcb->tx_buf->pnt%4) tcb->tx_buf->buf[tcb->tx_buf->pnt++]='\0';

    RELEASE_TX_LOCK(tcb);

    return tcb->tx_buf->pnt;
}

// append a data chunk to tx buffer
static int sctp_make_data(sctp_tcb_t *tcb, data_hdr_t *buf, int len)
{
    if( tcb->state != e_state_accepting && tcb->state != e_state_connected)
    {
        LOGI("[%s:%u] invalid state %d\n", __func__, __LINE__, tcb->state);
        errno = EINVAL;
        return 0;
    }

    ACQUIRE_TX_LOCK(tcb);

    if( tcb->tx_buf->pnt == 0 )
    {
        tcb->tx_buf->pnt = sctp_set_header(tcb, (void*)tcb->tx_buf->buf);
    }

    // append chunk
    sctp_chunk_t *chunk = (void*)(tcb->tx_buf->buf + tcb->tx_buf->pnt);

    chunk->type = e_type_data;
    chunk->flags = 0x07; // UBE - unordered single packet
    tcb->tx_tsn += 1;
    *(unsigned int*)chunk->value = htonl(tcb->tx_tsn);
LOGV("[%s:%u] sent tsn=%u len=%d\n", __func__, __LINE__, tcb->tx_tsn, len);
    int pnt = tcb->tx_buf->pnt;

    pnt += sizeof(sctp_chunk_t) + sizeof(tcb->tx_tsn);

    if( pnt + len < tcb->tx_buf->max )
    {
        if( buf && len > 0 )
        {
            __builtin_memcpy(tcb->tx_buf->buf + pnt, buf, len);
            pnt += len;
        }
        chunk->length = htons(pnt - tcb->tx_buf->pnt);
        tcb->tx_buf->pnt = pnt;
        // padding
        while(tcb->tx_buf->pnt%4) tcb->tx_buf->buf[tcb->tx_buf->pnt++]='\0';
    }
    else
    {
        LOGI("[%s:%u] buffer overflow!\n", __func__, __LINE__);
        errno = EAGAIN;
        len = -1;
    }

    RELEASE_TX_LOCK(tcb);

    return len;
}

// rfc4960 sec 3.2. @length does not count any chunk padding
// @b must be pointer to sctp_chunk_t or sctp_parameter_t
// which both have size of 4
#define SCTP_ALIGNMENT(n) ((((n)+3)/4)*4)
#define SCTP_ELEM_SIZE(b) SCTP_ALIGNMENT(ntohs((b)->length))
#define SCTP_ELEM_NEXT(b) ((void*)(((char*)(b))+SCTP_ALIGNMENT(ntohs((b)->length))))

static int sctp_make_abort(sctp_tcb_t *tcb)
{
LOGI("[%s:%u] ABORT\n", __func__, __LINE__);
    ACQUIRE_TX_LOCK(tcb);

    sctp_common_t *hdr = (void*)tcb->tx_buf->buf;

    if( tcb->tx_buf->pnt == 0 )
    {
        tcb->tx_buf->pnt = sctp_set_header(tcb, hdr);
    }
    // append chunk
    sctp_chunk_t *chunk = (void*)(tcb->tx_buf->buf + tcb->tx_buf->pnt);

    __builtin_memset(chunk, 0, sizeof(sctp_chunk_t));

    chunk->type = e_type_abort;

    // set T bit as per rfc4960 section 8.5.1. B)
    if( hdr->verification_tag == tcb->tx_tag )
    {
        chunk->flags |= 1;
    }
    // no error causes
    chunk->length = htons(sizeof(sctp_chunk_t));

    tcb->tx_buf->pnt += ntohs(chunk->length);
    // padding
    while(tcb->tx_buf->pnt%4) tcb->tx_buf->buf[tcb->tx_buf->pnt++]='\0';

    RELEASE_TX_LOCK(tcb);

    return tcb->tx_buf->pnt;
}

static int sctp_make_shutdown(sctp_tcb_t *tcb)
{
LOGI("[%s:%u] Shutdown\n", __func__, __LINE__);
    ACQUIRE_TX_LOCK(tcb);

    sctp_common_t *hdr = (void*)tcb->tx_buf->buf;

    if( tcb->tx_buf->pnt == 0 )
    {
        tcb->tx_buf->pnt = sctp_set_header(tcb, hdr);
    }
    // append chunk
    sctp_chunk_t *chunk = (void*)(tcb->tx_buf->buf + tcb->tx_buf->pnt);

    __builtin_memset(chunk, 0, sizeof(sctp_chunk_t));

    chunk->type = e_type_shutdown;

    // 8 bytes
    chunk->length = htons(sizeof(sctp_chunk_t) + 4);
    ((uint32_t*)chunk->value)[0] = htonl(tcb->rx_tsn);

    tcb->tx_buf->pnt += ntohs(chunk->length);

    // padding
    while(tcb->tx_buf->pnt%4) tcb->tx_buf->buf[tcb->tx_buf->pnt++]='\0';

    RELEASE_TX_LOCK(tcb);

    return tcb->tx_buf->pnt;
}

static int  sctp_make_reconfig(sctp_tcb_t *tcb, int sn)
{
    ACQUIRE_TX_LOCK(tcb);

    sctp_common_t *hdr = (void*)tcb->tx_buf->buf;

    if( tcb->tx_buf->pnt == 0 )
    {
        tcb->tx_buf->pnt = sctp_set_header(tcb, hdr);
    }
    // append chunk
    sctp_chunk_t *chunk = (void*)(tcb->tx_buf->buf + tcb->tx_buf->pnt);

    __builtin_memset(chunk, 0, sizeof(sctp_chunk_t));

    chunk->type = e_tyep_reconfigure;

    chunk->length = htons(sizeof(sctp_chunk_t) + 14);
    ((uint32_t*)chunk->value)[0] = htonl(tcb->recnf_sn);
    ((uint32_t*)chunk->value)[1] = htonl(tcb->recnf_sn);
    ((uint32_t*)chunk->value)[2] = htonl(tcb->tx_tsn);
    tcb->recnf_sn += 1;
    ((uint16_t*)chunk->value)[6] = htons(sn);

    tcb->tx_buf->pnt += ntohs(chunk->length);

    // padding
    while(tcb->tx_buf->pnt%4) tcb->tx_buf->buf[tcb->tx_buf->pnt++]='\0';

    RELEASE_TX_LOCK(tcb);

    return tcb->tx_buf->pnt;
}

static int  sctp_parse_param(unsigned short opt)
{
    int j;
    for(j = 0; j < SCTP_OPTIONS_LEN; j++)
    {
        if( opt == stcp_options[j] ) break;
    }

    return j < SCTP_OPTIONS_LEN ? 1 : 0;
}

// rfc4960 sec. 3.3.2. & 3.3.3. chunk init and init_ack
struct cb_init {
    unsigned int initial_tag;
    unsigned int a_rwnd;        // sender's rwnd
    unsigned short tx_streams;  // sender's tx streams count
    unsigned short rx_streams;  // sender's rx streams count
    unsigned int initial_tsn;
    sctp_parameter_t param[0];  // boundary determined by overal length
};

struct cookie_t
{
    unsigned char  hmac_sha1[20];
    union {
        unsigned char  hmac_text[4];
        unsigned int   timestamp;      // in host order
    };
    // from common header
    stcpaddr_t     peer_addr;
    stcpaddr_t     self_addr;
    // from init chunk
    struct cb_init peer_init[0];   // size determined by overal size
};

struct sack_t
{
    unsigned int   tsnack;
    unsigned int   a_rwnd;
    unsigned short n_gaps;
    unsigned short n_dups;
};

static int sctp_make_init(sctp_tcb_t *tcb, sctp_parameter_t *param, int psize)
{
    ACQUIRE_TX_LOCK(tcb);

    sctp_common_t *hdr = (void*)tcb->tx_buf->buf;

    int pnt = sctp_set_header(tcb, hdr);

    tcb->tx_buf->pnt = pnt;

    sctp_chunk_t *chunk = hdr->chunk;

    __builtin_memset(chunk, 0, sizeof(sctp_chunk_t));

    chunk->type = e_type_init_ack;

    pnt += sizeof(sctp_chunk_t);

    struct cb_init * init = (void*)chunk->value;

    if( 0 == tcb->rx_tag ) tcb->rx_tag = (unsigned int)randk();

    init->initial_tag = tcb->rx_tag;
    init->a_rwnd = htonl(SCTP_RX_BUF_MAX);
    init->tx_streams = htons(tcb->tx_streams);
    init->rx_streams = htons(tcb->rx_streams);
    init->initial_tsn = htonl(tcb->tx_tsn+1);
LOGV("[%s:%u] tcb->tx_streams=%d initial tsn=%u\n", __func__, __LINE__,
    tcb->tx_streams, ntohl(init->initial_tsn));
    pnt += sizeof(struct cb_init);

    // add parameters - ignore incoming @param for now
    {
        // rfc3758 FORWARD TSN
        param = init->param;
        param->type = htons(0xc000); // rfc3758 sec 3.1.
        param->length = htons(4);    // rfc3758 sec 3.1.
        pnt += ntohs(param->length);
    }

    chunk->length = htons(pnt - tcb->tx_buf->pnt);

    tcb->tx_buf->pnt = pnt;
    // padding
    while(tcb->tx_buf->pnt%4) tcb->tx_buf->buf[tcb->tx_buf->pnt++]='\0';

    RELEASE_TX_LOCK(tcb);

    return pnt;
}

static int sctp_make_sack(sctp_tcb_t *tcb)
{
LOGV("[%s:%u] SACK\n", __func__, __LINE__);
    ACQUIRE_TX_LOCK(tcb);

    if( tcb->tx_buf->pnt == 0 )
    {
        tcb->tx_buf->pnt = sctp_set_header(tcb, (void*)tcb->tx_buf->buf);
    }
    // append chunk
    sctp_chunk_t *chunk = (void*)(tcb->tx_buf->buf + tcb->tx_buf->pnt);

    __builtin_memset(chunk, 0, sizeof(sctp_chunk_t));

    chunk->type = e_type_sack;

    int len = sizeof(sctp_chunk_t);

    struct sack_t *sack = (void*) chunk->value;

    sack->tsnack = htonl(tcb->rx_tsn);
    sack->a_rwnd = htonl(tcb->rx_buf->max - tcb->rx_buf->pnt);
    sack->n_gaps = 0;
    sack->n_dups = 0;

    len += sizeof(*sack);

    chunk->length = htons(len);

    tcb->tx_buf->pnt += len;
    // padding
    while(tcb->tx_buf->pnt%4) tcb->tx_buf->buf[tcb->tx_buf->pnt++]='\0';

    RELEASE_TX_LOCK(tcb);

    return tcb->tx_buf->pnt;
}

// heartbeat-ack
static int sctp_make_hback(sctp_tcb_t *tcb, sctp_chunk_t *hb)
{
LOGI("[%s:%u] HEARBEAT-ACK\n", __func__, __LINE__);
    ACQUIRE_TX_LOCK(tcb);

    if( tcb->tx_buf->pnt == 0 )
    {
        tcb->tx_buf->pnt = sctp_set_header(tcb, (void*)tcb->tx_buf->buf);
    }
    // append chunk
    sctp_chunk_t *chunk = (void*)(tcb->tx_buf->buf + tcb->tx_buf->pnt);

    int len = ntohs(hb->length); // chunk header included
    // copy heartbeat chunk over
    memcpy(chunk, hb, len);
    // change chunk type
    chunk->type = e_type_heartbeat_ack;

    tcb->tx_buf->pnt += len;  // new tx buffer
    // padding
    while(tcb->tx_buf->pnt%4) tcb->tx_buf->buf[tcb->tx_buf->pnt++]='\0';

    RELEASE_TX_LOCK(tcb);

    return tcb->tx_buf->pnt;
}

// return utc seconds
static unsigned int sctp_utc_time(void)
{
    struct timespec  tv;
    clock_gettime(CLOCK_REALTIME, &tv);
    
    return (unsigned int)(tv.tv_sec);
}

static int sctp_make_cookie(sctp_tcb_t *tcb, struct cb_init *peer_init, int length)
{
    ACQUIRE_TX_LOCK(tcb);

    sctp_common_t *hdr = (void*)tcb->tx_buf->buf;
    sctp_chunk_t *chunk = hdr->chunk; // always first chunk

    sctp_parameter_t * param = (void*)(tcb->tx_buf->buf + tcb->tx_buf->pnt);

    param->type = htons(7); // rfc4960 section 3.3.3.1.
    param->length = htons(sizeof(sctp_parameter_t) + sizeof(struct cookie_t) + length);

    struct cookie_t *cookie = (void*)param->value;
    
    __builtin_memset(cookie, 0, sizeof(struct cookie_t));
    cookie->timestamp = sctp_utc_time();
    cookie->peer_addr = tcb->peer_addr;
    cookie->self_addr = tcb->self_addr;
    __builtin_memcpy(cookie->peer_init, peer_init, length);

    int  plen = sizeof(sctp_parameter_t) + sizeof(struct cookie_t) + length;
    // calculate hmac-sha1
    hmac_sha1(cookie->hmac_text,
              sizeof(struct cookie_t) - sizeof(cookie->hmac_sha1) + length,
              hmac_key, HMAC_KEY_LEN,
              cookie->hmac_sha1);

    chunk->length = htons(ntohs(chunk->length) + plen);

    tcb->tx_buf->pnt += plen;
    // padding
    while(tcb->tx_buf->pnt%4) tcb->tx_buf->buf[tcb->tx_buf->pnt++]='\0';

    // append init params - reject all options
    if( (plen = length - sizeof(struct cb_init)) > 0 )
    {
        // add Unrecognized Parameters
        param = (void*)(tcb->tx_buf->buf + tcb->tx_buf->pnt);
        param->type = htons(8); // rfc4960 section 3.2.2.
        param->length = htons(sizeof(*param)+plen);

        __builtin_memcpy(param->value, peer_init->param, plen);

        plen += sizeof(*param);
        // chunk->length may not align, count padding in
        chunk->length = htons(SCTP_ALIGNMENT(ntohs(chunk->length)) + plen);
    
        tcb->tx_buf->pnt += plen;
        // padding
        while(tcb->tx_buf->pnt%4) tcb->tx_buf->buf[tcb->tx_buf->pnt++]='\0';
    }

    RELEASE_TX_LOCK(tcb);

    return 0;
}

//
// rfc4960 sec 3.3.2.
// pre-treatment of init request:
// (1) check all option parameters and reject unknown/unsupported options
// (2) take a hmac-sha1 digest on common header and init chunk, append it
//     to init_ack as state-cookie and send it back to client
//
static int sctp_parse_init(sctp_tcb_t *tcb, sctp_chunk_t *chunk)
{
    int len = ntohs(chunk->length);

    len -= sizeof(sctp_chunk_t);

    struct cb_init * init = (void *)chunk->value;

    tcb->tx_tag = init->initial_tag;

    tcb->peer_wnd = ntohl(init->a_rwnd);

    if( tcb->rx_streams > ntohs(init->tx_streams) )
    {
        tcb->rx_streams = ntohs(init->tx_streams);
    }

    if( tcb->tx_streams > ntohs(init->rx_streams) )
    {
        tcb->tx_streams = ntohs(init->rx_streams);
    }

    tcb->rx_tsn = ntohl(init->initial_tsn);

    len -= sizeof(struct cb_init);

    sctp_parameter_t *param = init->param;
    int k;
    for( k = 0;
         k < len;
         k += SCTP_ELEM_SIZE(param), param = SCTP_ELEM_NEXT(param))
    {

    LOGV("[%s:%u] option type=%#.4X size=%d\n", __func__, __LINE__,
        ntohs(param->type), ntohs(param->length));

        // rfc4960 sec 3.3.2.
        // if we don't support the option, send abort?
        if( ! sctp_parse_param(ntohs(param->type)) ) break;
    }

    if( k < len )
    {
        sctp_make_abort(tcb);
    }
    else // k >= len
    {
        // generate init_ack
        sctp_make_init(tcb, init->param, k);
        // add parameters
        sctp_make_cookie(tcb, init, len - sizeof(*chunk));
    }

    // as per rfc4960 section 5.1.3., in order to defeat DoS attcks, 
    // tcb state should reset to null
    // TODO: investigation - with rtcweb the connection is point-to-point
    //tcb->state = e_state_null;

    return 0;
}

//
// received a response to init-ack
// ignore @chunk for now
//
static int sctp_parse_cookie_echo(sctp_tcb_t *tcb, sctp_chunk_t *chunk)
{
LOGV("[%s:%u] chunk length=%d\n", __func__, __LINE__, ntohs(chunk->length));

    // TODO: investigation - with rtcweb the connection is point-to-point
    // no tcb re-initialization is needed
    //struct cb_init *init = (void*)hdr->chunk->value;

//    tcb->state = e_state_connected;

    // send COOKIE ACK - rfc4960 section 3.3.12.
    sctp_common_t *hdr = (void*)tcb->tx_buf->buf;

    int pnt;

    if( (pnt = tcb->tx_buf->pnt) == 0 )
    {
        pnt = sctp_set_header(tcb, hdr);
    }

    chunk = hdr->chunk;

    chunk->type = e_type_cookie_ack;
    
    chunk->length = htons(sizeof(sctp_chunk_t));

    pnt += SCTP_ELEM_SIZE(chunk);

    tcb->tx_buf->pnt = pnt;

    return 0;
}

// rfc4960 section 3.3.1.
static int sctp_parse_data(sctp_tcb_t *tcb, sctp_chunk_t *chunk)
{
    int len = ntohs(chunk->length);

    // check tsn - rfc4960 section 3.3.1.
    struct {
        unsigned int  data_tsn;
        unsigned char data_hdr[0];
    }  *seg =  (void*)chunk->value;

    len -= sizeof(sctp_chunk_t) + sizeof(*seg);

    unsigned int tsn = ntohl(seg->data_tsn);

    int delta = (int)tsn - (int)tcb->rx_tsn;

    if( delta == 1 )
    {
        tcb->rx_tsn += 1;
    }
    
    // make ack in tx buffer
    sctp_make_sack(tcb);

    // indicate to upper layer
    // if a callback is there, call it
    data_recv(tcb->data_ctx, seg->data_hdr, len);

    // set off condition variable
    pthread_cond_signal(&tcb->cond);

    return 0;
}

static int sctp_write_ready(void *ctx)
{
    sctp_tcb_t *tcb = ctx;

    if( tcb->tx_tsn == tcb->tx_ack ||
        tcb->tx_tsn == tcb->tx_ack + 1 ||
        tcb->tx_tsn == tcb->tx_ack + 2 ||
        tcb->tx_tsn == tcb->tx_ack + 3)
    {
        return 1;
    }
    if( (int)tcb->tx_tsn < (int)tcb->tx_ack )
    {
        LOGI("[%s:%u] PANIC: invalid tsn %u vs acked %u\n", __func__, __LINE__,
            tcb->tx_tsn, tcb->tx_ack);
    }
    return 0;
}

int sctp_wait_writable(void *ctx, int timeout_ms)
{
    sctp_tcb_t *tcb = ctx;

    pthread_mutex_lock(tcb->write_lock);

    if( ! sctp_write_ready(tcb) )
    {
        pthread_cond_wait(tcb->write_cond, tcb->write_lock);
    }

    pthread_mutex_unlock(tcb->write_lock);

    return 0;
}

// rfc4960 section 3.3.4.
static int sctp_parse_sack(sctp_tcb_t *tcb, sctp_chunk_t *chunk)
{
    struct sack_t *sack = (void*) chunk->value;
    unsigned int atsn = ntohl(sack->tsnack);
    unsigned int ftsn = atsn + 1;
    unsigned short *ptn = (void*)(sack+1);
    int k;
    for(k = 0; k < ntohs(sack->n_gaps); k++)
    {
        LOGI("[%s:%u] gap[%u] ack=%u gap=[%u %u] a_rwnd=%u\n", __func__, __LINE__, k, atsn,
            atsn+ntohs(ptn[2*k+0]), atsn+ntohs(ptn[2*k+1]), sack->a_rwnd);
        ftsn = atsn+ntohs(ptn[2*k+1]);
    }
    if( ntohs(sack->n_gaps) > 0 )
    {
        // send a forward tsn to last tx tsn
        sctp_make_ftsn(tcb, ftsn);
    }
LOGV("[%s:%u] tcb->tx_ack=%u tcb->tx_tsn=%u\n", __func__, __LINE__, tcb->tx_ack, tcb->tx_tsn);
    tcb->tx_ack = atsn;

    pthread_mutex_lock(tcb->write_lock);
    if( sctp_write_ready(tcb) )
    {
        pthread_cond_signal(tcb->write_cond);
    }
    pthread_mutex_unlock(tcb->write_lock);

    return 0;
}

//
// receiving from dtls - @sctp_tcb can be null
// return number of bytes processed, negative if overflow
//
int   sctp_rx(void *dtls_ctx, void *data, int size)
{
    if( size < sizeof(sctp_common_t) ) return 0;

    sctp_common_t *hdr = data;

    // rfc4960 sec 3.1. 0 ports not allowed
    if( hdr->source_port==0 || hdr->destination_port==0 )
    {
        LOGV("[%s:%u] WARNING: null ports(%u %u)\n", __func__, __LINE__,
            hdr->source_port, hdr->destination_port);
        return size;
    }
    // checksum
    if( sctp_test_crc32c(hdr, size) )
    {
        LOGV("[%s:%u] WARNING: checksum error\n", __func__, __LINE__);
        return size;
    }

    sctp_tcb_t *tcb = dtls_get_sctp(dtls_ctx);

    if( tcb == 0 )
    {
        // find matching context
        tcb = sctp_fetch_tcb(dtls_ctx, hdr, size);
        
        if( tcb != 0 )
        {
            tcb->dtls_ctx = dtls_ctx;
            // link dtls to sctp
            dtls_set_sctp(dtls_ctx, tcb);
        }
        else
        {
            LOGV("[%s:%u] WARNING: no matching context\n", __func__, __LINE__);
            return size;
        }
    }
    if( tcb->dtls_ctx != dtls_ctx )
    {
        LOGV("[%s:%u] PANIC: mismatching context\n", __func__, __LINE__);
        return size;
    }
    // rfc4960 sec 3.1. verification tag must be 0 if not known
    if( tcb->rx_tag != hdr->verification_tag )
    {
        LOGV("[%s:%u] WARNING: wrong verification tag %.8X %.8X\n", __func__, __LINE__, tcb->rx_tag, hdr->verification_tag);
        return size;
    }
    if( tcb->tx_tag == 0 )
    {
        tcb->peer_addr.sin_port = hdr->source_port; // network order
    }
    // parse chunks
    int e = 0;
    sctp_chunk_t *chunk;
    int k;
    for( k = sizeof(sctp_common_t), chunk = hdr->chunk;
         k < size;
         k += SCTP_ELEM_SIZE(chunk), chunk = SCTP_ELEM_NEXT(chunk))
    {
        switch( chunk->type )
        {
        case e_type_data:
            LOGV("[%s:%u] INFO: e_type_data k=%d\n", __func__, __LINE__, k);
            e = sctp_parse_data(tcb, chunk);
            break;
        case e_type_init:
            LOGV("[%s:%u] INFO: e_type_init\n", __func__, __LINE__);
            // ignore if not the first packet in rx buffer
            if( k == sizeof(sctp_common_t) && hdr->verification_tag == 0 )
            {
                e = sctp_parse_init(tcb, chunk);
                // TODO: investigation 
                //dtls_set_sctp(dtls_ctx, 0);
                //sctp_reset_tcb(tcb); // tx_buf still valid
            }
            else
            {
                LOGV("[%s:%u] WARNING: init nonzero verification tag $%.8x\n",
                    __func__, __LINE__, hdr->verification_tag);
            }
            break;
        case e_type_init_ack:
            LOGV("[%s:%u] INFO: e_type_init_ack\n", __func__, __LINE__);
            break;
        case e_type_sack:
            LOGV("[%s:%u] INFO: e_type_sack\n", __func__, __LINE__);
            sctp_parse_sack(tcb, chunk);
            break;
        case e_type_heartbeat:
            LOGV("[%s:%u] INFO: e_type_heartbeat\n", __func__, __LINE__);
            e = sctp_make_hback(tcb, chunk);
            break;
        case e_type_heartbeat_ack:
            LOGV("[%s:%u] INFO: e_type_heartbeat_ack\n", __func__, __LINE__);
            break;
        case e_type_abort:
            LOGV("[%s:%u] INFO: e_type_abort\n", __func__, __LINE__);
            return -1; // to close session
            break;
        case e_type_shutdown:
            LOGI("[%s:%u] INFO: e_type_shutdown\n", __func__, __LINE__);
            sctp_make_shutdown(tcb);
            break;
        case e_type_shutdown_ack:
            LOGV("[%s:%u] INFO: e_type_shutdown_ack\n", __func__, __LINE__);
            // should send e_type_shutdown_complete
            break;
        case e_type_error:
            LOGI("[%s:%u] INFO: e_type_error\n", __func__, __LINE__);
            {
                int length = ntohs(chunk->length) - 4;
                LOGI("[%s:%u] OPERATION ERROR length=%d\n", __func__, __LINE__, length);
                dump_hex(chunk->value, length);
            }
            break;
        case e_type_cookie_echo:
            LOGV("[%s:%u] INFO: e_type_cookie_echo\n", __func__, __LINE__);
            // ignore if not the first packet in rx buffer
            if( k == sizeof(sctp_common_t) )
            {
                e = sctp_parse_cookie_echo(tcb, chunk);
                tcb->data_ctx = data_open(tcb, WEBRTC_STREAM_ID,
                                          ntohs(hdr->destination_port),
                                          ntohs(hdr->source_port));
                if( tcb->data_ctx == 0 )
                {
                    LOGV("[%s:%u] WARNING: null tcb->data_ctx=\n", __func__, __LINE__);
                }
            }
            break;
        case e_type_cookie_ack:
            LOGV("[%s:%u] INFO: e_type_cookie_ack\n", __func__, __LINE__);
            break;
        case e_type_ecne:
            LOGV("[%s:%u] INFO: e_type_ecne\n", __func__, __LINE__);
            break;
        case e_type_cwr:
            LOGI("[%s:%u] INFO: e_type_cwr\n", __func__, __LINE__);
            break;
        case e_type_shutdown_complete:
            LOGI("[%s:%u] INFO: e_type_shutdown_complete\n", __func__, __LINE__);
            // how to reuse tcb from here?
            break;
        case e_tyep_reconfigure:
            LOGI("[%s:%u] INFO: e_tyep_reconfigure\n", __func__, __LINE__);
            break;
        case e_type_forward_tsn:
            LOGI("[%s:%u] INFO: e_type_forward_tsn\n", __func__, __LINE__);
            break;
        default:
            LOGI("[%s:%u] INFO: unknown type %d\n", __func__, __LINE__, chunk->type);
            break;
        }
        
        if(e < 0) break;  // 
    }

    // transmit tx buffer
    sctp_tx(tcb);

    return size;
}

//
// sending to dtls - @dtls_ctx must be valid
//
int   sctp_tx(void *ctx)
{
    sctp_tcb_t *tcb = ctx;

    ACQUIRE_TX_LOCK(tcb);

    int size = 0;
    
    if( tcb->tx_buf->pnt > 0 )
    {
        sctp_common_t *hdr = (void*)tcb->tx_buf->buf;

        sctp_make_crc32c(hdr, tcb->tx_buf->pnt);
    
//LOGV("[%s:%u] tx size=%d\n", __func__, __LINE__, tcb->tx_buf->pnt);
//dump_hex(tcb->tx_buf->buf, tcb->tx_buf->pnt);

        size = dtls_tx_userdata(tcb->dtls_ctx, tcb->tx_buf->buf, tcb->tx_buf->pnt);

        tcb->tx_buf->pnt = 0; // reset tx buffer
    }

    RELEASE_TX_LOCK(tcb);

    return size;
}

// put a data chunk into tx buffer - @data must a type of data_hdr_t*
int  sctp_send_out(void *tcb, void *data, int size)
{
    int e = sctp_make_data(tcb, data, size);

    sctp_tx(tcb);

    return e;
}

// halt a sctp client session - call from dtls
void  sctp_halt(void *dtls_ctx)
{
    LOGV("[%s:%u] halt sctp client\n", __func__, __LINE__);
    sctp_tcb_t *tcb = dtls_get_sctp(dtls_ctx);
    if( tcb )
    {
        if( tcb->data_ctx ) data_halt(tcb->data_ctx);

        sctp_reuse_tcb(tcb);
    }
    else LOGV("[%s:%u] tcb not found\n", __func__, __LINE__);
}

int  sctp_to_webrtc(void *tcb, char *text, int len)
{
    int e = 0;

    void *data_ctx = ((sctp_tcb_t*)tcb)->data_ctx;

    if( data_ctx )
    {
        e = webrtc_send(data_ctx, WEBRTC_STREAM_ID, text, len);
    }

    return e;
}

int  sctp_send_close(void *tcb)
{
    int e = sctp_make_shutdown(tcb);
    // force tx
    sctp_tx(tcb);

    return e;
}

int  sctp_send_reconfigure(void *tcb, int stream_number)
{
    int e = sctp_make_reconfig(tcb, stream_number);
    // force tx
    sctp_tx(tcb);

    return e;
}

////////////////////////////////////////////////////////////////////////////////

// adopted from rfc4960 Appedix C.

#define CRC32C_POLY 0x1EDC6F41
#define CRC32C(c,d) (c=(c>>8)^crc_c[(c^(d))&0xFF])

static unsigned int crc_c[256]=
{
 0x00000000, 0xF26B8303, 0xE13B70F7, 0x1350F3F4, 0xC79A971F, 0x35F1141C,
 0x26A1E7E8, 0xD4CA64EB, 0x8AD958CF, 0x78B2DBCC, 0x6BE22838, 0x9989AB3B,
 0x4D43CFD0, 0xBF284CD3, 0xAC78BF27, 0x5E133C24, 0x105EC76F, 0xE235446C,
 0xF165B798, 0x030E349B, 0xD7C45070, 0x25AFD373, 0x36FF2087, 0xC494A384,
 0x9A879FA0, 0x68EC1CA3, 0x7BBCEF57, 0x89D76C54, 0x5D1D08BF, 0xAF768BBC,
 0xBC267848, 0x4E4DFB4B, 0x20BD8EDE, 0xD2D60DDD, 0xC186FE29, 0x33ED7D2A,
 0xE72719C1, 0x154C9AC2, 0x061C6936, 0xF477EA35, 0xAA64D611, 0x580F5512,
 0x4B5FA6E6, 0xB93425E5, 0x6DFE410E, 0x9F95C20D, 0x8CC531F9, 0x7EAEB2FA,
 0x30E349B1, 0xC288CAB2, 0xD1D83946, 0x23B3BA45, 0xF779DEAE, 0x05125DAD,
 0x1642AE59, 0xE4292D5A, 0xBA3A117E, 0x4851927D, 0x5B016189, 0xA96AE28A,
 0x7DA08661, 0x8FCB0562, 0x9C9BF696, 0x6EF07595, 0x417B1DBC, 0xB3109EBF,
 0xA0406D4B, 0x522BEE48, 0x86E18AA3, 0x748A09A0, 0x67DAFA54, 0x95B17957,
 0xCBA24573, 0x39C9C670, 0x2A993584, 0xD8F2B687, 0x0C38D26C, 0xFE53516F,
 0xED03A29B, 0x1F682198, 0x5125DAD3, 0xA34E59D0, 0xB01EAA24, 0x42752927,
 0x96BF4DCC, 0x64D4CECF, 0x77843D3B, 0x85EFBE38, 0xDBFC821C, 0x2997011F,
 0x3AC7F2EB, 0xC8AC71E8, 0x1C661503, 0xEE0D9600, 0xFD5D65F4, 0x0F36E6F7,
 0x61C69362, 0x93AD1061, 0x80FDE395, 0x72966096, 0xA65C047D, 0x5437877E,
 0x4767748A, 0xB50CF789, 0xEB1FCBAD, 0x197448AE, 0x0A24BB5A, 0xF84F3859,
 0x2C855CB2, 0xDEEEDFB1, 0xCDBE2C45, 0x3FD5AF46, 0x7198540D, 0x83F3D70E,
 0x90A324FA, 0x62C8A7F9, 0xB602C312, 0x44694011, 0x5739B3E5, 0xA55230E6,
 0xFB410CC2, 0x092A8FC1, 0x1A7A7C35, 0xE811FF36, 0x3CDB9BDD, 0xCEB018DE,
 0xDDE0EB2A, 0x2F8B6829, 0x82F63B78, 0x709DB87B, 0x63CD4B8F, 0x91A6C88C,
 0x456CAC67, 0xB7072F64, 0xA457DC90, 0x563C5F93, 0x082F63B7, 0xFA44E0B4,
 0xE9141340, 0x1B7F9043, 0xCFB5F4A8, 0x3DDE77AB, 0x2E8E845F, 0xDCE5075C,
 0x92A8FC17, 0x60C37F14, 0x73938CE0, 0x81F80FE3, 0x55326B08, 0xA759E80B,
 0xB4091BFF, 0x466298FC, 0x1871A4D8, 0xEA1A27DB, 0xF94AD42F, 0x0B21572C,
 0xDFEB33C7, 0x2D80B0C4, 0x3ED04330, 0xCCBBC033, 0xA24BB5A6, 0x502036A5,
 0x4370C551, 0xB11B4652, 0x65D122B9, 0x97BAA1BA, 0x84EA524E, 0x7681D14D,
 0x2892ED69, 0xDAF96E6A, 0xC9A99D9E, 0x3BC21E9D, 0xEF087A76, 0x1D63F975,
 0x0E330A81, 0xFC588982, 0xB21572C9, 0x407EF1CA, 0x532E023E, 0xA145813D,
 0x758FE5D6, 0x87E466D5, 0x94B49521, 0x66DF1622, 0x38CC2A06, 0xCAA7A905,
 0xD9F75AF1, 0x2B9CD9F2, 0xFF56BD19, 0x0D3D3E1A, 0x1E6DCDEE, 0xEC064EED,
 0xC38D26C4, 0x31E6A5C7, 0x22B65633, 0xD0DDD530, 0x0417B1DB, 0xF67C32D8,
 0xE52CC12C, 0x1747422F, 0x49547E0B, 0xBB3FFD08, 0xA86F0EFC, 0x5A048DFF,
 0x8ECEE914, 0x7CA56A17, 0x6FF599E3, 0x9D9E1AE0, 0xD3D3E1AB, 0x21B862A8,
 0x32E8915C, 0xC083125F, 0x144976B4, 0xE622F5B7, 0xF5720643, 0x07198540,
 0x590AB964, 0xAB613A67, 0xB831C993, 0x4A5A4A90, 0x9E902E7B, 0x6CFBAD78,
 0x7FAB5E8C, 0x8DC0DD8F, 0xE330A81A, 0x115B2B19, 0x020BD8ED, 0xF0605BEE,
 0x24AA3F05, 0xD6C1BC06, 0xC5914FF2, 0x37FACCF1, 0x69E9F0D5, 0x9B8273D6,
 0x88D28022, 0x7AB90321, 0xAE7367CA, 0x5C18E4C9, 0x4F48173D, 0xBD23943E,
 0xF36E6F75, 0x0105EC76, 0x12551F82, 0xE03E9C81, 0x34F4F86A, 0xC69F7B69,
 0xD5CF889D, 0x27A40B9E, 0x79B737BA, 0x8BDCB4B9, 0x988C474D, 0x6AE7C44E,
 0xBE2DA0A5, 0x4C4623A6, 0x5F16D052, 0xAD7D5351
};

unsigned int generate_crc32c(unsigned char *buffer, int length)
{
    int i;
    unsigned int crc32 = 0xffffffffL;  // ~0L is incorrect on 64-bit see errata
    unsigned int result;
    unsigned int byte0, byte1, byte2, byte3;
    for (i = 0; i < length; i++)
    {
        CRC32C(crc32, buffer[i]);
    }
    result = ~crc32;
    byte0 = result & 0xff;
    byte1 = (result>>8) & 0xff;
    byte2 = (result>>16) & 0xff;
    byte3 = (result>>24) & 0xff;

    crc32 = ((byte0 << 24) | (byte1 << 16) | (byte2 << 8) | byte3);

    return crc32;
}


////////////////////////////////////////////////////////////////////////////////
#ifdef LOCAL_BUILD
void   dtls_set_sctp(void *dtls_ctx, void *sctp_tcb)
{
}
void * dtls_get_sctp(void *dtls_ctx)
{
    return 0;
}

static unsigned int reflect_32(unsigned int b)
{
    int i;
    unsigned int rw = 0L;
    for (i = 0; i < 32; i++)
    {
        if (b & 1) rw |= 1 << (31 - i);

        b >>= 1;
    }
    return rw;
}

static unsigned int build_crc_table(int index)
{
    int i;
    unsigned int rb = reflect_32(index);
    for (i = 0; i < 8; i++)
    {
        if (rb & 0x80000000L)
        {
            rb = (rb << 1) ^ CRC32C_POLY;
        }
        else
        {
            rb <<= 1;
        }
    }
    return reflect_32 (rb);
}

int main(int argc, char *argv[])
{
    int j;

    if( argc == 2 && 0 == __builtin_memcmp(argv[1], "make-table", 11) )
    {
        for(j = 0; j < 256; j++)
        {
             printf(" 0x%08X,", build_crc_table(j));
             if ((j%6) == 5) printf ("\n");
        }
        printf("\n");
    }
    else if( argc == 2 && 0 == __builtin_memcmp(argv[1], "run-test", 9) )
    {
        unsigned char pkt[] = 
        {
            0x13, 0x88, 0x13, 0x88, 0x00, 0x00, 0x00, 0x00, 0xcb, 0x5a,
            0x7e, 0x73, 0x01, 0x00, 0x00, 0x56, 0x8d, 0xcc, 0xe1, 0x8e,
            0x00, 0x10, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x55, 0xd9,
            0x29, 0x23, 0xc0, 0x00, 0x00, 0x04, 0x80, 0x08, 0x00, 0x09,
            0xc0, 0x0f, 0xc1, 0x80, 0x82, 0x00, 0x00, 0x00, 0x80, 0x02,
            0x00, 0x24, 0x44, 0xe1, 0xce, 0x68, 0x9b, 0x21, 0x52, 0x42,
            0x62, 0x6c, 0x50, 0x52, 0x68, 0x55, 0x43, 0x30, 0xaf, 0xab,
            0xfd, 0x10, 0xa7, 0x36, 0x16, 0x6e, 0x7b, 0x64, 0x3e, 0x56,
            0x63, 0xa7, 0xf5, 0x4c, 0x80, 0x04, 0x00, 0x06, 0x00, 0x01,
            0x00, 0x00, 0x80, 0x03, 0x00, 0x06, 0x80, 0xc1, 0x00, 0x00
        };
        int e = sctp_test_crc32c((void*)pkt, sizeof(pkt));
        printf("[%s:%u] e=%d\n", __func__, __LINE__, e);
    }
    else
    {
        printf("%s make-table | run-test\n", argv[0]);
    }

    return 0;
}

#endif // LOCAL_BUILD
