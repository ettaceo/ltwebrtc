// file : dtls5764.c dtls6347.c
// date : 01/11/2020 12/25/2019
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "dtls5764.h"
#include "cryptlib/prng.h"
#include "x509cert.h"
#include "ecdheapi.h"
#include "aessuite.h"
#include "srtp3711.h"
#include "sctpdtls.h"

#define LOGV(...)
//#define LOGV printf
//#define LOGI(...)
#define LOGI printf

#define RECORD_PER_MESSAGE 0
#define EXTENSION_RFC7627 0   // extended mater secrete
#define EXTENSION_RFC5077 0   // Session Ticket
#define EXTENSION_SIGNATURE_ALGORITHMS 0 // rfc5246 (7.4.1.4.1)
                                         // Servers MUST NOT send this extension
#define REQUEST_CLIENT_CERTIFICATE 0

#define HANDSHAKE_MESSAGE_MAX (1<<14)

// forward declaration
typedef struct dtls_ctx_t dtls_ctx_t;

typedef struct hs_ctx_t
{
    union {
        dtls_hello_t hello;
    }        parsed_msg;  // dtls_hello_t

    tls_random_t server_random; // for server hello
    tls_random_t client_random; // from client hello

    tls_sessionid_t session_id; // from client hello

    uint8_t cipher_suite[2];    // selected cipher suite
    uint8_t srtp_profile[2];    // selected srtp profile
    uint8_t hash_signature[2];  // selected signature algorith

    uint8_t ec_secret_ptr[256]; // ec shared secret
    int     ec_secret_len;

    unsigned char master_secret[48]; // length 48 per rfc5246 sec 8.1.

    union {
        uint8_t  u[256];
    }  msg_hash;

    void    *key_pair;    // ec key context
#if EXTENSION_RFC7627
    int      hs_rfc7627;  // rfc-7627 Extended Master Secret
#endif
#if EXTENSION_RFC5077
    int      hs_rfc5077;  // rfc-5077 Session Ticket TLS
#endif

    int      expected_msg_type;
    int      msg_length;
    int      msg_recved;
    int      rcv_maxlen;  // if @rcv_buffer is allocated
    uint8_t *rcv_buffer;  // dtls_handshake_t*

    int      rcv_seqnum;  // receive sequence number
    int      snd_seqnum;  // send sequence number

    int      hsm_maxlen;  //
    int      hsm_length;
    uint8_t *hsm_buffer;  // whole conversation

}   hs_ctx_t; // g_hs_ctx[DTLS_HSCTX_MAX];

typedef struct dtls_ctx_t
{
    void    *ice_session; // icep_t
    void    *sctp_tcb;    // sctp_tcb_t

    struct sockaddr_in from;
    uint8_t  content_type;
    int      inception;    // system ticks
    int      epoch_rx;
    int      sequence_rx;
    int      epoch_tx;
    int      sequence_tx;

    union {
        dtls_rechdr_t  rechdr;
        uint8_t        record[13];
    };

    int      out_sent;  // already sent
    int      out_mark;  // end of out buffer
    uint8_t  proto_out[DTLS_MESSAGE_MAX];

    hs_ctx_t proto_ctx[1];

    // rfc5246 section 6.3 Key Calculation
    struct dtls_key_block_t {
        uint8_t client_write_key[TLS_ENC_KEY_LENGTH];
        uint8_t server_write_key[TLS_ENC_KEY_LENGTH];
        uint8_t client_write_IV[TLS_FIXED_IV_LENGTH];
        uint8_t server_write_IV[TLS_FIXED_IV_LENGTH];
    } dtls_key_block;  // for dtls "finished" message

    // rfc5764 section 4.1 Key Derivation
    struct srtp_key_block_t {
        uint8_t client_write_SRTP_master_key[SRTP_MASTER_KEY_LENGTH];
        uint8_t server_write_SRTP_master_key[SRTP_MASTER_KEY_LENGTH];
        uint8_t client_write_SRTP_master_salt[SRTP_MASTER_SALT_LENGTH];
        uint8_t server_write_SRTP_master_salt[SRTP_MASTER_SALT_LENGTH];
    } srtp_key_block;

}   dtls_ctx_t;


// rfc6347 sec 4.2.1 - diff fron record layer version number
static uint8_t dtl_server_version[2]={254, 253};

#define  DTLS_PEERS_MAX 2

static dtls_ctx_t g_dtls_ctx[DTLS_PEERS_MAX];

////////////////////////////////////////////////////////////////////////////////
extern void *ice_session_peer(void *sess);
extern int   ice_send_pkt(void *sess, uint8_t *pkt, int len);
extern int   ice_send_rec(void *sess, uint8_t *rec, uint8_t *body, int blen);
extern void *get_srtp_cryptos(void *sess);
extern void *set_srtp_cryptos(void *sess, void *tx_crypt, void *rx_crypt);
extern void  dtls_setup_srtp(dtls_ctx_t *ctx);
extern void  dtls_close_srtp(void *sess);
extern void  ice_source_srtp(void *sess);
extern void  ice_set_dtls_ctx(void *sess, void *ctx);
extern void *ice_get_dtls_ctx(void *sess);

static int dtls_tx_handshake(dtls_ctx_t *dtls_ctx, void *data, int size);
static int create_server_hello(dtls_ctx_t *dtls_ctx, dtls_handshake_t *dhs);
static int create_server_certificate(dtls_ctx_t *dtls_ctx, dtls_handshake_t *dhs);
static int create_server_key_exchange(dtls_ctx_t *dtls_ctx, dtls_handshake_t *dhs);
static int create_server_hello_done(dtls_ctx_t *dtls_ctx, dtls_handshake_t *dhs);
#if EXTENSION_RFC5077
static int create_session_ticket(dtls_ctx_t *dtls_ctx, dtls_handshake_t *dhs);
#endif
#if REQUEST_CLIENT_CERTIFICATE
static int create_certificate_request(dtls_ctx_t *dtls_ctx, dtls_handshake_t *dhs);
#endif
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

////////////////////////////////////////////////////////////////////////////////

// rfc5246 (A.5.)
void print_cipher_suites(uint8_t *ptr, int len)
{
    int j;
    for(j=0; j < len; j+=2)
    {
        LOGV("(%#.2x %#.2x) ", ptr[j], ptr[j+1]);
    }
    LOGV("**end\n");
}

void print_signature_algorithms(uint8_t *u, int size)
{
    int cnt = BE2_TO_HOST(u);
    u += 2;
    int pnt;
    for( pnt=0; pnt < cnt; pnt += 2)
    {
        LOGV("[%s:%u] hash-algorithm(%.2x) signature_algorithm(%.2x)\n",
           __func__, __LINE__,  u[pnt+0], u[pnt+1]);
    }
}

void print_use_srtp(uint8_t *u, int size)
{
    int cnt = BE2_TO_HOST(u);
    int pnt;
    LOGV("[%s:%u] cnt=%d size=%d\n", __func__, __LINE__,  cnt, size);
    u += 2;
    for( pnt=0; pnt < cnt; pnt += 2)
    {
        LOGV("[%s:%u] SRTPProtectionProfile %.2x %.2x\n",
           __func__, __LINE__,  u[pnt+0], u[pnt+1]);
    }
    cnt = u[pnt++];
    LOGV("[%s:%u] srtp_mki count=%d\n", __func__, __LINE__,  cnt);
}

// rfc5246 (A.4.1.)
void print_extensions(tls_extension_t *ex, int len)
{
    while (len > 0 )
    {
        int size = BE2_TO_HOST(ex->extension_size);
        if( sizeof(*ex) +  size > len)
        {
            LOGV("[%s:%u] incomplete extention size=%d got %d\n",
                __func__, __LINE__,  (int)sizeof(*ex) + +size, len);
            return;
        }
        int type = BE2_TO_HOST(ex->type);
        LOGV("[%s:%u] extention type=%d size=%d\n", __func__, __LINE__, 
            type, size);
        switch( type)
        {
        case TYPE_SIGNATURE_ALGORITHMS:
            print_signature_algorithms(ex->extension_data, size);
            break;
        case TYPE_USE_SRTP:
            print_use_srtp(ex->extension_data, size);
            break;
        default:
            break;
        }

        ex = (void*)(ex->extension_data + size);
        len -= sizeof(*ex) +  size;
    }
}

void print_hello(dtls_hello_t *h)
{
    LOGV("[%s:%u] version(%u.%u)\n", __func__, __LINE__,
        h->version[0], h->version[1]);
    LOGV("[%s:%u] session_id_len=%d\n", __func__, __LINE__,
        h->session_id_len);
    LOGV("[%s:%u] cookie_len=%d\n", __func__, __LINE__,
        h->cookie_len);

    LOGV("[%s:%u] cipher_suites_len=%d\n", __func__, __LINE__,
        h->cipher_suites_len);
    if( h->cipher_suites_len > 0 )
    {
        int j=0;
        for(; j < h->cipher_suites_len; j+=2)
        {
            LOGV("[%s:%u] cipher_suites {%.2x %.2x}\n", __func__, __LINE__,
                h->cipher_suites_ptr[j+0], h->cipher_suites_ptr[j+1]);
        }
    }

    LOGV("[%s:%u] compression_methods_len=%d compression_methods[0]=%u\n",
        __func__, __LINE__,
        h->compression_methods_len, h->compression_methods_ptr[0]);
    LOGV("[%s:%u] extensions_len=%d \n", __func__, __LINE__,
        h->extensions_len);

    if( h->extensions_len > 0 )
    {
        print_extensions((void*)h->extentions_ptr, h->extensions_len);
    }
    LOGV("[%s:%u] use_srtp.profile_len=%d srtp_mki_len=%d\n", __func__, __LINE__,
        h->use_srtp.profiles_len, h->use_srtp.srtp_mki_len);
    if( h->use_srtp.profiles_len > 0 )
    {
        int j;
        for(j=0; j < h->use_srtp.profiles_len; j+=2)
        {
            LOGV("[%s:%u] use_srtp srtp profile {%.2x %.2x}\n", __func__, __LINE__,
                h->use_srtp.profiles_ptr[j+0], h->use_srtp.profiles_ptr[j+1]);
        }
    }
}

static int  accept_client_hello(dtls_ctx_t *dtls_ctx);
static int  accept_client_finished(dtls_ctx_t *dtls_ctx);

// return 0 if use_srtp found
// or negative
static int  parse_use_srtp(dtls_hello_t *ch)
{
    tls_extension_t *ex=(void*)ch->extentions_ptr;
    int len = ch->extensions_len;
    use_srtp_t *use_srtp = &(ch->use_srtp);
    memset(use_srtp, 0, sizeof(use_srtp_t));

    while (len > 0 )
    {
        int size = BE2_TO_HOST(ex->extension_size);
        if( sizeof(*ex) +  size > len)
        {
            LOGV("[%s:%u] incomplete extention size=%d got %d\n",
                __func__, __LINE__,  (int)sizeof(*ex) + +size, len);
            return -1;
        }

        if( TYPE_USE_SRTP == BE2_TO_HOST(ex->type) )
        {
            use_srtp->profiles_len = BE2_TO_HOST(ex->extension_data);
            // @size must at least 2 + use_srtp->profiles_len + 1
            if( (use_srtp->profiles_len >= size-2) ||
                (use_srtp->profiles_len%2) )
            {
                LOGV("[%s:%u] invalid use_srtp profiles length %d size=%d\n",
                    __func__, __LINE__,  use_srtp->profiles_len, size);
                use_srtp->profiles_len = 0;
                return -2;
            }
            use_srtp->profiles_ptr = ex->extension_data + 2;

            use_srtp->srtp_mki_len =
                ex->extension_data[2 + use_srtp->profiles_len];

            if(use_srtp->profiles_len + use_srtp->srtp_mki_len != size - 2 -1 )
            {
                LOGV("[%s:%u] invalid use_srtp profiles_len %d mkilen %d size=%d\n",
                    __func__, __LINE__, 
                    use_srtp->profiles_len, use_srtp->srtp_mki_len, size);
                use_srtp->profiles_len = 0;
                use_srtp->srtp_mki_len = 0;
                return -3;
            }

            if( use_srtp->srtp_mki_len > 0 )
            {
                use_srtp->srtp_mki_ptr = 
                    ex->extension_data + 2 + use_srtp->profiles_len + 1;
            }
            return 0;
        }

        ex = (void*)(ex->extension_data + size);
        len -= sizeof(*ex) +  size;
    }
    LOGV("[%s:%u] use_srtp profiles not found\n", __func__, __LINE__);

    return -4;
}

__attribute__((unused))
static int  check_hello_extension(dtls_hello_t *ch, int type)
{
    tls_extension_t *ex=(void*)ch->extentions_ptr;
    int len = ch->extensions_len;
    while (len > 0 )
    {
        int size = BE2_TO_HOST(ex->extension_size);
        if( sizeof(*ex) +  size > len)
        {
            LOGV("[%s:%u] incomplete extention size=%d got %d\n",
                __func__, __LINE__,  (int)sizeof(*ex) + +size, len);
            return -1;
        }
        if( type == BE2_TO_HOST(ex->type) )
        {
            return 1;
        }
        ex = (void*)(ex->extension_data + size);
        len -= sizeof(*ex) +  size;
    }
    return 0; // not found
}

// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
//select cipher suite (most close to apple homekit)
//0xCC,0xA9 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 Y Y [RFC7905]
//0xCC,0xA8 TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 Y Y [RFC7905]
//0xC0,0x2F TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 Y Y [RFC5289]
//0xC0,0x2B TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 Y Y [RFC5289]
static uint8_t s_cipher_suite[2]={0xc0, 0x2b}; // must match select_srtp_profile()

static int select_cipher_suite(struct hs_ctx_t *hs_ctx, dtls_hello_t *ch)
{
    if( ch->cipher_suites_len <= 0 ) return -1;

    hs_ctx->cipher_suite[0] = 0;
    hs_ctx->cipher_suite[1] = 0;

    int j=0;
    for(; j < ch->cipher_suites_len; j+=2)
    {
        if( ch->cipher_suites_ptr[j+0] == s_cipher_suite[0] &&
            ch->cipher_suites_ptr[j+1] == s_cipher_suite[1] )
        {
            hs_ctx->cipher_suite[0] = ch->cipher_suites_ptr[j+0];
            hs_ctx->cipher_suite[1] = ch->cipher_suites_ptr[j+1];
            LOGV("[%s:%u] selected cipher_suite {%.2x %.2x}\n", __func__, __LINE__,
                hs_ctx->cipher_suite[0], hs_ctx->cipher_suite[1]);
            return 0;
        }
    }
    LOGV("[%s:%u] no matching cipher_suite found\n", __func__, __LINE__);

    return -2;
}

// parse extension "signature algorithms"
//  0x0401  RSA sha256
//  0x0403  ECDSA sha256
static uint8_t s_hash_signature[2]={0x04, 0x03};  // ECDSA sha256

static int select_hash_signature(struct hs_ctx_t *hs_ctx, dtls_hello_t *ch)
{
    tls_extension_t *ex=(void*)ch->extentions_ptr;
    int len = ch->extensions_len;

    while (len > 0 )
    {
        int size = BE2_TO_HOST(ex->extension_size);
        if( sizeof(*ex) +  size > len)
        {
            LOGV("[%s:%u] incomplete extention size=%d got %d\n",
                __func__, __LINE__,  (int)sizeof(*ex) + +size, len);
            return -1;
        }

        if( TYPE_SIGNATURE_ALGORITHMS == BE2_TO_HOST(ex->type) )
        {
            uint8_t *u = ex->extension_data;
            int cnt = BE2_TO_HOST(u);
            u += 2;
            int pnt;
            for( pnt=0; pnt < cnt; pnt += 2)
            {
                if( u[pnt+0] == s_hash_signature[0] &&
                    u[pnt+1] == s_hash_signature[1] )
                {
                    hs_ctx->hash_signature[0] = u[pnt+0];
                    hs_ctx->hash_signature[1] = u[pnt+1];
                    LOGV("[%s:%u] selected hash_signature(%.2x %.2x)\n", __func__, __LINE__,
                    hs_ctx->hash_signature[0], hs_ctx->hash_signature[1]);
                    return 0;
                }
            }
        }

        ex = (void*)(ex->extension_data + size);
        len -= sizeof(*ex) +  size;
    }
    LOGV("[%s:%u] no matching signature algorithm in extention!\n",__func__, __LINE__);

    return -2;
}

//
//  accepts srtp profiles:
//  {0x00, 0x08} SRTP_AEAD_AES_256_GCM [RFC7714]
//  {0x00, 0x07} SRTP_AEAD_AES_128_GCM [RFC7714]
//  {0x00, 0x01} SRTP_AES128_CM_HMAC_SHA1_80 [RFC5764]
//  {0x00, 0x02} SRTP_AES128_CM_HMAC_SHA1_32 [RFC5764]
static uint8_t s_srtp_profile[2]={0x00, 0x01}; // SRTP_AES128_CM_HMAC_SHA1_80

static int select_srtp_profile(struct hs_ctx_t *hs_ctx, dtls_hello_t *ch)
{
    // chromuim supports {0x00, 0x01} and {0x00, 0x02}
    // firefox supports {0x00, 0x01} {0x00, 0x02} {0x00, 0x07} {0x00, 0x08}
    use_srtp_t *use_srtp = &(ch->use_srtp);

    if( use_srtp->profiles_len <= 0 ) return -1;

    hs_ctx->srtp_profile[0] = 0;
    hs_ctx->srtp_profile[1] = 0;

    int j=0;
    for(; j < use_srtp->profiles_len; j+=2)
    {
        if( use_srtp->profiles_ptr[j+0] == s_srtp_profile[0] &&
            use_srtp->profiles_ptr[j+1] == s_srtp_profile[1] )
        {
            hs_ctx->srtp_profile[0] = use_srtp->profiles_ptr[j+0];
            hs_ctx->srtp_profile[1] = use_srtp->profiles_ptr[j+1];
            break;
        }
    }
    LOGV("[%s:%u] selected srtp profile {%.2x %.2x}\n", __func__, __LINE__,
        hs_ctx->srtp_profile[0], hs_ctx->srtp_profile[1]);

    // return 0 if we support the cipher
    return (hs_ctx->srtp_profile[1] == 0 ? -2 : 0);
}

// rfc5246 (7.4.1.2.) rfc6347 (4.2.1.)
//struct {
//  ProtocolVersion client_version;
//  Random random;
//  SessionID session_id;
//  opaque cookie<0..2^8-1>;
//  CipherSuite cipher_suites<2..2^16-2>;
//  CompressionMethod compression_methods<1..2^8-1>;
//  select (extensions_present) {
//  case false:
//  struct {};
//  case true:
//    Extension extensions<0..2^16-1>;
//  };
//} ClientHello;
//

// return number of bytes parsed after dtls_handshake_t.
static int parse_client_hello(struct hs_ctx_t *hs_ctx)
{
    dtls_hello_t *ch = &hs_ctx->parsed_msg.hello;

    ch->size = hs_ctx->msg_length;
    ch->data = hs_ctx->rcv_buffer + sizeof(dtls_handshake_t);

    ch->parsed_ok = 0;

    int  pnt=0;
    ch->version = ch->data + pnt;
    pnt += 2;
    if( pnt >= ch->size ) goto exit;
    
    if( ch->version[0] != dtl_server_version[0] ||
        ch->version[1] != dtl_server_version[1] )
    {
        // firefox 7.1 seen [0.28]
        LOGV("[%s:%u] unknown ClientHello version %d %d\n",
            __func__, __LINE__, ch->version[0], ch->version[1]);
        goto exit;
    }

    ch->random = ch->data + pnt;
    pnt += sizeof(tls_random_t);
    if( pnt >= ch->size ) goto exit;

    // save client random
    memcpy(&(hs_ctx->client_random), ch->random, sizeof(tls_random_t));

    ch->session_id_len= ch->data[pnt++];
    if( ch->session_id_len > 0 )
    {
        ch->session_id_ptr = ch->data + pnt;
        pnt += ch->session_id_len;
    }
    if( pnt >= ch->size ) goto exit;

    ch->cookie_len = ch->data[pnt++];
    if( ch->cookie_len > 0 )
    {
        ch->cookie_ptr = ch->data + pnt;
        pnt += ch->cookie_len;
    }
    if( pnt >= ch->size ) goto exit;

    ch->cipher_suites_len = BE2_TO_HOST(ch->data + pnt);
    pnt += 2;
    if( ch->cipher_suites_len > 0 )
    {
        ch->cipher_suites_ptr = ch->data + pnt;
        pnt += ch->cipher_suites_len;
    }
    if( pnt >= ch->size ) goto exit;

    ch->compression_methods_len = ch->data[pnt++];
    if( ch->compression_methods_len > 0 )
    {
        ch->compression_methods_ptr = ch->data + pnt;
        pnt += ch->compression_methods_len;
    }

    // check if extensions present
    if( pnt < ch->size )
    {
        ch->extensions_len = BE2_TO_HOST(ch->data + pnt);
        pnt += 2;
        if( ch->extensions_len > 0 )
        {
            ch->extentions_ptr = ch->data + pnt;
            pnt += ch->extensions_len;
        }
    }
    if( pnt > ch->size ) goto exit;

    // must have extention (use_srtp) as per rfc5764
    if( 0 > parse_use_srtp(ch) ) goto exit;

    if( 0 > select_hash_signature(hs_ctx, ch) ) goto exit;

    if( 0 > select_cipher_suite(hs_ctx, ch) ) goto exit;

    if( 0 > select_srtp_profile(hs_ctx, ch) ) goto exit;
#if EXTENSION_RFC5077
    hs_ctx->hs_rfc5077 = check_hello_extension(ch, TYPE_SESSION_TICKET_TLS);
#endif
#if EXTENSION_RFC7627
    hs_ctx->hs_rfc7627 = check_hello_extension(ch, TYPE_EXTENDED_MASTER_SCRETE);
#endif
    ch->parsed_ok = 1;

//    print_hello(ch);

exit:

    return ch->parsed_ok ? pnt : -1;
}

#if REQUEST_CLIENT_CERTIFICATE
static int parse_client_certificate(struct hs_ctx_t *hs_ctx)
{
    int       size = hs_ctx->msg_length;
    // copy message to conversation buffer
    memcpy(hs_ctx->hsm_buffer+hs_ctx->hsm_length,
           hs_ctx->rcv_buffer, sizeof(dtls_handshake_t) + size);
    hs_ctx->hsm_length += sizeof(dtls_handshake_t) + size;

    hs_ctx->expected_msg_type = e_client_key_exchange;

    return 0;
}

static int parse_certificate_verify(struct hs_ctx_t *hs_ctx)
{
    int       size = hs_ctx->msg_length;
    // copy message to conversation buffer
    memcpy(hs_ctx->hsm_buffer+hs_ctx->hsm_length,
           hs_ctx->rcv_buffer, sizeof(dtls_handshake_t) + size);
    hs_ctx->hsm_length += sizeof(dtls_handshake_t) + size;

    hs_ctx->expected_msg_type = e_finished;

    return 0;
}
#endif

// return number of bytes parsed after dtls_handshake_t.
static int parse_client_key_exchange(struct hs_ctx_t *hs_ctx)
{
    int       size = hs_ctx->msg_length;
    uint8_t * data = hs_ctx->rcv_buffer + sizeof(dtls_handshake_t);

    // copy message to conversation buffer
    memcpy(hs_ctx->hsm_buffer+hs_ctx->hsm_length,
           hs_ctx->rcv_buffer, sizeof(dtls_handshake_t) + size);
    hs_ctx->hsm_length += sizeof(dtls_handshake_t) + size;

#if EXTENSION_RFC7627
    if( hs_ctx->hs_rfc7627 > 0 )
    {
        hs_ctx->hs_rfc7627 = hs_ctx->hsm_length;
        LOGV("[%s:%u] ** hs_rfc7627=%d\n", __func__, __LINE__, hs_ctx->hs_rfc7627);
    }
#endif
    // rfc4492 5.7.

    int  pnt=0;

    // public key length
    int ec_public_key_len = data[pnt++];
    uint8_t *ec_public_key_ptr = data + pnt;
    // derive shared secret

    hs_ctx->ec_secret_len = calc_pre_master(hs_ctx->key_pair,
                                ec_public_key_ptr, ec_public_key_len,
                                hs_ctx->ec_secret_ptr);

    pnt += ec_public_key_len;

    // expect next message to be (encrypted) FINISHED
#if REQUEST_CLIENT_CERTIFICATE
    hs_ctx->expected_msg_type = e_certificate_verify;
#else
    hs_ctx->expected_msg_type = e_finished;
#endif
    return pnt;
}

// return number of bytes parsed after dtls_handshake_t.
// return negative number to abort
static int parse_client_finished(struct hs_ctx_t *hs_ctx)
{
    dtls_handshake_t *hs_msg_ptr = (void*)hs_ctx->rcv_buffer;
    int hs_msg_len = BE3_TO_HOST(hs_msg_ptr->length);
    if( hs_msg_len != VERIFY_DATA_LENGTH ) // rfc5246 7.4.9. "12 octets"
    {
        LOGV("[%s:%u] PANIC: finished length=%d\n",
            __func__, __LINE__, hs_msg_len);
        return -1;
    }

    // calculate "verify_data" rfc5246 7.4.9.
    uint8_t *verify_data = __builtin_alloca(hs_msg_len);
    uint8_t *label_seed = __builtin_alloca(64);
    // rfc5246 7.4.9. "client finished"
    int ls_len = sprintf((char*)label_seed, "client finished");
    // SHA256_DIGEST_LENGTH=32
    hash_sha256_array(label_seed + ls_len, hs_ctx->hsm_buffer, hs_ctx->hsm_length);
    ls_len += SHA256_DIGEST_LENGTH;

    int e = PRF(hs_ctx->master_secret, sizeof(hs_ctx->master_secret),
                label_seed, ls_len,
                verify_data, hs_msg_len);

    // compared verify_data
    if( e != hs_msg_len ||
        0 != memcmp(verify_data, hs_msg_ptr->fragment_data, hs_msg_len) )
    {
//LOGV("[%s:%u] finished length=%d\n", __func__, __LINE__, hs_msg_len);
//dump_hex((void*)(hs_msg_ptr+1), hs_msg_len);
//LOGV("[%s:%u] verify_data len=%d\n", __func__, __LINE__, e);
//if( e > 0 ) dump_hex(verify_data, e);
        return -2;
    }
LOGV("[%s:%u] client finished verified length=%d\n", __func__, __LINE__, hs_msg_len);
    // save message to conversation buffer
    int       size = hs_ctx->msg_length;
    memcpy(hs_ctx->hsm_buffer+hs_ctx->hsm_length,
           hs_ctx->rcv_buffer, (sizeof(dtls_handshake_t) + size));
    hs_ctx->hsm_length += (sizeof(dtls_handshake_t) + size);

    return hs_msg_len;
}

//
// aes keys are generated in change_cipher_spec()
// return plaintext length or negative
//
static int dtls_decrypt_message(dtls_ctx_t *ctx, dtls_rechdr_t *rechdr)
{
    uint8_t *msg_ptr = (void*)(rechdr + 1);
    int      enc_len = BE2_TO_HOST(rechdr->length);

    // msg_len must contain explicit-nonce and tag
    if( enc_len < TLS_RECORD_IV_LENGTH + TLS_GCM_TAG_LENGTH )
    {
        LOGV("[%s:%u] PANIC: invalid msg_len(%d)\n", __func__, __LINE__, enc_len);
        return 0;
    }

    int dec_len = enc_len - (TLS_RECORD_IV_LENGTH + TLS_GCM_TAG_LENGTH);

    // gcm nonce from rfc5288 section 3.0
    struct {
        uint8_t salt[TLS_FIXED_IV_LENGTH]; // 4 bytes
        uint8_t nonce_explicit[TLS_RECORD_IV_LENGTH]; // 8 bytes
    } gcm_nonce={(0)};

    memcpy(gcm_nonce.salt,
           ctx->dtls_key_block.client_write_IV, TLS_FIXED_IV_LENGTH);
    memcpy(gcm_nonce.nonce_explicit, msg_ptr, TLS_RECORD_IV_LENGTH);

    // aad from rfc5246
    struct {
        uint8_t  seq_num[8]; // record epoch + sequence_number
        uint8_t  type; // 22
        uint8_t  version[2];
        uint8_t  length[2];
    } additional_data={(0)};

    memcpy(additional_data.seq_num, rechdr->epoch, 8);
    additional_data.type = rechdr->content_type;
    additional_data.version[0] = rechdr->protocol_version[0];
    additional_data.version[1] = rechdr->protocol_version[1];
    V2_TO_BE(dec_len, additional_data.length);

    aes_parms_t *parms = __builtin_alloca(sizeof(aes_parms_t));
    memset(parms, 0, sizeof(aes_parms_t));

    parms->ciphertext_ptr = msg_ptr + TLS_RECORD_IV_LENGTH;
    parms->ciphertext_len = dec_len;
    // tag at the tail
    parms->tag_ptr = msg_ptr + enc_len - TLS_GCM_TAG_LENGTH;

    parms->iv_ptr = (void*)&gcm_nonce;
    parms->iv_len = sizeof(gcm_nonce);

    parms->aad_ptr = (void*)&additional_data;
    parms->aad_len = sizeof(additional_data);

    parms->key_ptr = ctx->dtls_key_block.client_write_key;

    parms->plaintext_ptr = __builtin_alloca(dec_len);
    parms->plaintext_len = dec_len; // not in use

    int len = gcm_128_decrypt(parms);

//    LOGV("[%s:%u] decrypted len=%d\n", __func__, __LINE__, len);
//    if( len > 0 ) dump_hex(parms->plaintext_ptr, len);

    if( len >= 0 && len <= dec_len )
    {
        memcpy(msg_ptr, parms->plaintext_ptr, len);
    }
    else
    {
        len = -1;  // decryption failed
    }

    // return number of bytes decrypted
    return len;
}

//
// return message length or negative error code
//
static int alert_received(dtls_ctx_t *ctx, void *msg, int max)
{
    struct {
        uint8_t alert_level;
        uint8_t description;
    } * alert = msg;

    if( max < sizeof(*alert) )
    {
        LOGV("[%s:%u] incomplete alert message %d.\n", __func__, __LINE__, max);
        return max;
    }
    // chromium sends {warning(1),close_notify(0)}
    LOGV("[%s:%u] %.2x %.2x\n", __func__, __LINE__,
        alert->alert_level, alert->description);

    // level 1 = warning, 2 = fatal
    return alert->alert_level==2 ? 0 : sizeof(*alert);
}

//
// return bytes processed, if positive, it must be the message size
//
static int dtls_handshake(dtls_ctx_t *ctx, dtls_handshake_t *msg, int max)
{
    // rfc6347 - expect flen >= sizeof(dtls_handshake_t)
    if( max < sizeof(dtls_handshake_t) )
    {
        LOGV("[%s:%u] fragment too small.\n", __func__, __LINE__);
        return - e_decode_error;
    }

    LOGV("[%s:%u] expecting epoch=%d sequence=%d\n",
        __func__, __LINE__, ctx->epoch_rx, ctx->sequence_rx);

    // rfc5246 (7.4.) encapsulated in TLSPlaintext 

    int hs_mlen = BE3_TO_HOST(msg->length); // message length
    int hs_flen = BE3_TO_HOST(msg->fragment_length);
    int hs_foff = BE3_TO_HOST(msg->fragment_offset);

    if( max < sizeof(dtls_handshake_t) + hs_flen )
    {
        LOGV("[%s:%u] PANIC: fragment length mismatch\n",
        __func__, __LINE__);
        return - e_decode_error;
    }

    int value_to_return = sizeof(dtls_handshake_t) + hs_flen;

    // get handshake message sequence number
    int hs_mseq = BE2_TO_HOST(msg->message_seq);

    struct hs_ctx_t *hs_ctx = ctx->proto_ctx;

    if( hs_mseq == 0 && hs_ctx->expected_msg_type == 0 )
    {
        // allocate handshake context and set message type
        hs_ctx->expected_msg_type = msg->msg_type;
    }

    int hs_message_type = msg->msg_type;

	if( hs_ctx->expected_msg_type != hs_message_type )
	{
        LOGV("[%s:%u] handshake message type mismatch %d %d\n",
            __func__, __LINE__, hs_ctx->expected_msg_type,  hs_message_type);
        return value_to_return;  // ignore
    }
    // reset next message type
    hs_ctx->expected_msg_type = e_handshake_max;

	if( hs_ctx->rcv_seqnum != hs_mseq )
	{
        LOGV("[%s:%u] handshake seq %d!=%d\n",  __func__, __LINE__,
            hs_mseq, hs_ctx->rcv_seqnum);
        return - e_unexpected_message;  // abort
    }

    if( hs_mlen < hs_foff + hs_flen )
    {
        LOGV("[%s:%u] handshake invalid fragment\n",  __func__, __LINE__);
        return - e_decode_error;
    }
    // if this is the 1st fragment, set message length
    // otherwise validate message length
    if( hs_ctx->msg_length == 0 )
    {
        hs_ctx->msg_length = hs_mlen;
    }
    else if( hs_ctx->msg_length != hs_mlen)
    {
        LOGV("[%s:%u] inconsistent message length(%d %d)\n",
            __func__, __LINE__, hs_ctx->msg_length, hs_mlen);
        return - e_decode_error;
    }
    // check if message is fragmented
    if( hs_mlen != hs_flen )
    {
        // allocate message buffer for fragmented message

        if( hs_ctx->rcv_maxlen > 0 &&
		    hs_ctx->rcv_maxlen < hs_mlen + sizeof(dtls_handshake_t))
        {
            // free previously allocated message buffer
            free(hs_ctx->rcv_buffer);
            hs_ctx->rcv_buffer = 0;
            hs_ctx->rcv_maxlen = 0;
        }

        if( hs_ctx->rcv_maxlen == 0 )
        {
            hs_ctx->rcv_maxlen = hs_mlen + sizeof(dtls_handshake_t);
            hs_ctx->rcv_buffer = malloc(hs_ctx->rcv_maxlen);
            //
            dtls_handshake_t *hs_msg = (void*)hs_ctx->rcv_buffer;
            memcpy(hs_msg, msg, sizeof(dtls_handshake_t));
            // for hash purpose, make message of 1 fragment
            V3_TO_BE(0, hs_msg->fragment_offset);
            V3_TO_BE(hs_mlen, hs_msg->fragment_length);
        }

        memcpy(hs_ctx->rcv_buffer + sizeof(dtls_handshake_t) + hs_foff,
            msg->fragment_data, hs_flen);

        hs_ctx->msg_recved += hs_flen;
    }
    else // non-fragmenetd message, do in-place parse
    {
        if( hs_ctx->rcv_maxlen > 0 )
        {
            hs_ctx->rcv_maxlen  = 0;
            if( hs_ctx->rcv_buffer ) free(hs_ctx->rcv_buffer);
        }
        hs_ctx->msg_length =
        hs_ctx->msg_recved = hs_flen;

        hs_ctx->rcv_buffer = (void*)msg;
    }

    if( hs_ctx->msg_length > hs_ctx->msg_recved )
    {
        LOGV("[%s:%u] type=%d frag message %d recvd %d\n", __func__, __LINE__,
            hs_message_type, hs_ctx->msg_length, hs_ctx->msg_recved);
        // need more fragments of the message
        return value_to_return;
    }

    int e = 0;

    switch(hs_message_type)
    {
    case e_hello_request:
        LOGV("[%s:%u] IGNORED: e_hello_request max=%d\n", __func__, __LINE__, max);
        break;
    case e_client_hello:
        if( hs_ctx->hsm_buffer )
        {
            // client hello in progress
            LOGV("[%s:%u] ignore client-hello seq=%d\n",
                __func__, __LINE__, hs_mseq);
        }
        else
        {
            // parse and process
            e = parse_client_hello(hs_ctx);
            if( e >= 0 )
            {
                e = accept_client_hello(ctx);
            }
            else
            {
                LOGV("[%s:%u] PANIC parse_client_hello() seq=%d\n",
                __func__, __LINE__, hs_mseq);
                e = -1;
            }
        }
        break;
    case e_server_hello:
        break;
#if REQUEST_CLIENT_CERTIFICATE
    case e_certificate:
        e = parse_client_certificate(hs_ctx);
        break;
#endif
    case e_server_key_exchange:
        break;
    case e_certificate_request:
        break;
    case e_server_hello_done:
        break;
#if REQUEST_CLIENT_CERTIFICATE
    case e_certificate_verify:
        e = parse_certificate_verify(hs_ctx);
        break;
#endif
    case e_client_key_exchange:
        e = parse_client_key_exchange(hs_ctx);
        e = 0;
        break;
    case e_finished:
        e = parse_client_finished(hs_ctx);
#if EXTENSION_RFC5077
        if( e >= 0 && hs_ctx->hs_rfc5077 )
        {
            dtls_handshake_t *dhs = (void*)(hs_ctx->hsm_buffer + hs_ctx->hsm_length);
            e = create_session_ticket(ctx, dhs);
            dtls_tx_handshake(ctx, dhs, e);
            hs_ctx->hsm_length += e;
        }
#endif
        if( e >= 0 )
        {
            e = accept_client_finished(ctx);
        }
        break;
    default:
        LOGV("[%s:%u] PANIC: unknown handshake type max=%d\n",
            __func__, __LINE__, max);
        break;
    }

    if( e >= 0 )
    {
        // increment receive sequence number
        hs_ctx->rcv_seqnum += 1;

        // reset message buffer
        hs_ctx->msg_length = hs_ctx->msg_recved = 0;
        if( hs_ctx->rcv_maxlen == 0 ) hs_ctx->rcv_buffer = 0;
    }

    // return message length or negative error code
    return  e >= 0 ? value_to_return : e;
}

//
// return message length or negative error code
//
static int change_cipher_spec(dtls_ctx_t *ctx, uint8_t *msg, int max)
{
    if( msg[0] != 0x01 ) // change_cipher_spec==1
    {
        LOGV("[%s:%u] PANIC: unknown value msg[0]=%.2x max=%d\n",
            __func__, __LINE__, msg[0], max);
        return - e_illegal_parameter;
    }

    struct hs_ctx_t *hs_ctx = ctx->proto_ctx;

    if( hs_ctx->ec_secret_len <= 0 )
    {
        LOGV("[%s:%u] PANIC: ec_secret_len=%d\n",
            __func__, __LINE__, hs_ctx->ec_secret_len);
        return - e_unexpected_message;
    }

    int e = 0;

    unsigned char label_seed[256]={(0)};
    int ls_len=0;

#if EXTENSION_RFC7627
    if( hs_ctx->hs_rfc7627 > 0 )
    {
        // make master secret - rfc7627 sec 3. and sec 4.
        ls_len = sprintf((char*)label_seed, "extended master secret");
        hash_sha256_array(label_seed + ls_len, hs_ctx->hsm_buffer, hs_ctx->hs_rfc7627);
        ls_len += SHA256_DIGEST_LENGTH;
    }
    else
    {
        // make master secret - rfc5246 sec 8.1.
        ls_len = sprintf((char*)label_seed, "master secret");
        memcpy(label_seed + ls_len, &hs_ctx->client_random, sizeof(tls_random_t));
        ls_len += sizeof(tls_random_t);
        memcpy(label_seed + ls_len, &hs_ctx->server_random, sizeof(tls_random_t));
        ls_len += sizeof(tls_random_t);
    }
#else
    // make master secret - rfc5246 sec 8.1.
    ls_len = sprintf((char*)label_seed, "master secret");
    memcpy(label_seed + ls_len, &hs_ctx->client_random, sizeof(tls_random_t));
    ls_len += sizeof(tls_random_t);
    memcpy(label_seed + ls_len, &hs_ctx->server_random, sizeof(tls_random_t));
    ls_len += sizeof(tls_random_t);
#endif // EXTENSION_RFC7627

    e = PRF(hs_ctx->ec_secret_ptr, hs_ctx->ec_secret_len, label_seed, ls_len,
            hs_ctx->master_secret, sizeof(hs_ctx->master_secret));
    if( e <= 0 )
    {
        LOGV("[%s:%u] PANIC: master secret PRF=%d\n", __func__, __LINE__, e);
        return - e_internal_error;
    }

    // delete pre_master_secret from memeory as per rfc5246 8.1.
    memset(hs_ctx->ec_secret_ptr, 0, hs_ctx->ec_secret_len);

    // TLS key derivation - rfc5246 sec 6.3.
    ls_len = sprintf((char*)label_seed, "key expansion");
    memcpy(label_seed + ls_len, &hs_ctx->server_random, sizeof(tls_random_t));
    ls_len += sizeof(tls_random_t);
    memcpy(label_seed + ls_len, &hs_ctx->client_random, sizeof(tls_random_t));
    ls_len += sizeof(tls_random_t);
    e = PRF(hs_ctx->master_secret, sizeof(hs_ctx->master_secret),
            label_seed, ls_len,
            (void*)&(ctx->dtls_key_block), sizeof(ctx->dtls_key_block));
    if( e <= 0 )
    {
        LOGV("[%s:%u] PANIC: key expansion PRF=%d\n", __func__, __LINE__, e);
        return - e_internal_error;
    }

    // SRTP key derivation - rfc5764 sec 4.2.
    // make lable + seeds - rfc5705 sec 4.
    ls_len = sprintf((char*)label_seed, "EXTRACTOR-dtls_srtp");
    memcpy(label_seed + ls_len, &hs_ctx->client_random, sizeof(tls_random_t));
    ls_len += sizeof(tls_random_t);
    memcpy(label_seed + ls_len, &hs_ctx->server_random, sizeof(tls_random_t));
    ls_len += sizeof(tls_random_t);

    e = PRF(hs_ctx->master_secret, sizeof(hs_ctx->master_secret),
            label_seed, ls_len,
            (void*)&(ctx->srtp_key_block), sizeof(ctx->srtp_key_block));

    if( e <= 0 )
    {
        LOGV("[%s:%u] PANIC: EXTRACTOR-dtls_srtp PRF=%d\n", __func__, __LINE__, e);
        return - e_internal_error;
    }
#ifdef DTLS_SRTP_OFF
    LOGV("[%s:%u] DTLS_SRTP_OFF dtls_setup_srtp disabled\n", __func__, __LINE__);
#else
    // set srtp crypto context
    dtls_setup_srtp(ctx);
#endif

    // TODO: increase epoch
    ctx->epoch_rx += 1;
    ctx->sequence_rx = ~0; // to compensate increment afterward

    // return number of bytes processed
    return 1;
}

int  get_protocol_version(uint8_t *rec, int *major, int *minor)
{
    // at record level
    if( major ) *major = rec[1];
    if( minor ) *minor = rec[2];

    // tls -> ver 3.x
    // tls 1.2 (rfc5246) -> ver 3.3
    // dtls 1.2 (rfc6347 ) -> ver 254.253

    return (rec[1]<<8)|(rec[2]);
}

int get_record_size(uint8_t *rec, int len, int dtls)
{
    int hlen = (dtls?DTLS_REC_HEADER_SIZE :TLS_REC_HEADER_SIZE);
    
    if(len < hlen ) return 0; // no enough data

    if( dtls )
    {
        LOGV("[%s:%u] dtls epoch=%u seq=%u\n", __func__, __LINE__,
          BE2_TO_HOST(rec+3), (uint32_t)BE6_TO_HOST(rec+5));
    }
    return BE2_TO_HOST(rec+hlen-2) + hlen;
}

int get_fragment_size(int8_t *rec, int len, int dtls)
{
    int hlen = (dtls?DTLS_REC_HEADER_SIZE :TLS_REC_HEADER_SIZE);
    
    if(len < hlen ) return 0; // no enough data

    if( dtls )
    {
        LOGV("[%s:%u] dtls epoch=%u seq=%u\n", __func__, __LINE__,
          BE2_TO_HOST(rec+3), (uint32_t)BE6_TO_HOST(rec+5));
    }
    return BE2_TO_HOST(rec+hlen-2);
}

// @sess is ice_session
void  dtls_cleanup_ctx(void *sess)
{
    dtls_ctx_t *ctx=0;
    int i;

    dtls_close_srtp(sess);

    // search known dtls session
    for(i = 0; i < DTLS_PEERS_MAX; i++)
    {
	    ctx = g_dtls_ctx + i;

        if( ctx->ice_session == sess) break;
    }
    if( i == DTLS_PEERS_MAX)
    {
        LOGV("[%s:%u] session %p not found!\n", __func__, __LINE__, sess);
        return;
    }

    sctp_halt(ctx); // halt a client session

    struct hs_ctx_t *hs_ctx = ctx->proto_ctx;

    if( hs_ctx->key_pair )
    {
        exit_ec_keypair(hs_ctx->key_pair);
    }
    // if hs_ctx->rcv_maxlen==0, don't free hs_ctx->rcv_buffer
    if( hs_ctx->rcv_maxlen > 0 && hs_ctx->rcv_buffer )
    {
        free(hs_ctx->rcv_buffer);
    }
    if( hs_ctx->hsm_buffer )
    {
        free(hs_ctx->hsm_buffer);
    }

    memset(hs_ctx, 0, sizeof(struct hs_ctx_t));

    memset(ctx, 0, sizeof(dtls_ctx_t));
}

static void * dtls_lookup_ctx(uint8_t *record, void *sess)
{
    dtls_ctx_t *ctx=ice_get_dtls_ctx(sess);
    int i;
    int rx_epoch = BE2_TO_HOST(record+3);
    int rx_sequence = (int)BE6_TO_HOST(record+5);
/*
    // search known dtls session
    if( ctx == 0 )
    {
        for(i = 0; i < DTLS_PEERS_MAX; ctx = 0, i++)
        {
            ctx = g_dtls_ctx + i;

            // rfc6347 sec 4.1. epoch and sequence must match
            if( ctx->epoch_rx != rx_epoch ) continue;
            if( ctx->sequence_rx != rx_sequence ) continue;
            if( ctx->ice_session == sess) break;
        }
        if( ctx ) ice_set_dtls_ctx(sess, ctx);
    }
*/
    // assigned new dtls peer context if this initiates a handshake
    if( ctx == 0 &&
        e_handshake == record[0] &&
        //0 == rx_sequence && // client hello may be ignored until use_candidate
        0 == rx_epoch )
    {
        for(i = 0; i < DTLS_PEERS_MAX; ctx = 0, i++)
        {
	        ctx = g_dtls_ctx + i;

            if( ctx->ice_session ==0 )
            {
                ctx->content_type = record[0];
                ctx->inception = 1;
                ctx->ice_session = sess;
                struct sockaddr_in *sa = ice_session_peer(sess);
                ctx->from = *sa;
                ctx->epoch_rx = 0;
                ctx->sequence_rx = rx_sequence;
                break;
            }
        }
    }

    if( ctx != 0 )
    {
        ice_set_dtls_ctx(sess, ctx);
        //LOGV("[%s:%u] current dtls[%d] epoch=%u seq=%u\n",
        //    __func__, __LINE__, i, ctx->epoch_rx, ctx->sequence_rx);
    }
    else
    {
        LOGV("[%s:%u] ignore message epoch=%d seq=%d\n",
            __func__, __LINE__, rx_epoch, rx_sequence);
    }

    return ctx; //(i < DTLS_PEERS_MAX ? ctx : 0);
}

// @description should be enum of AlertDescription as defined in rfc5246
int dtls_send_alert(dtls_ctx_t *dtls_ctx, int description)
{
    int k = 0;
    uint8_t  rec[32];
    // follow rfc6347 record layer
    // content-type
    rec[k++] = e_alert;
    // protocol version
    rec[k++] = dtl_server_version[0];
    rec[k++] = dtl_server_version[1];
    // epoch
    V2_TO_BE(dtls_ctx->epoch_tx, rec+k);
    k += 2;
    // sequence high 16-bits
    V2_TO_BE(0, rec+k);
    k += 2;
    //  sequence low 32-bits
    V4_TO_BE(dtls_ctx->sequence_tx, rec+k);
    k += 4;
    // length
    V2_TO_BE(2, rec+k);
    k += 2;
    // Alert
    rec[k++] = 2; // fatal
    rec[k++] = description;
    LOGV("[%s:%u] Alert (%d bytes) seq_tx=%d\n", __func__, __LINE__, k, dtls_ctx->sequence_tx);
    dump_hex(rec, k);

    dtls_ctx->sequence_tx += 1;

    return ice_send_pkt(dtls_ctx->ice_session, rec, k);
}

extern void ice_halt_session(void *sess);

//
// udp packet @data may contain multiple dtls records
// each record may contain mulitple messages
// return value, if positive, indicates reply bytes
//
int dtls_service(uint8_t *data, int size, void *sess)
{
    struct sockaddr_in *sa = ice_session_peer(sess);
    LOGV("[%s:%u] udp data size=%d from %s:%u\n", __func__, __LINE__,
        size, inet_ntoa(sa->sin_addr), ntohs(sa->sin_port));
    (void)sa;

    uint8_t *record_ptr = data;
    int      record_max = size;
    int      record_len = 0;

    int e = 0;

record_entry:

    // need complete record block
    record_len = get_record_size(record_ptr, record_max, 1);

    if( record_len <= 0 )
    {
        if( record_max > 0 )
        {
            dump_hex(record_ptr, record_max);
            LOGI("[%s:%u] PANIC: incomplete record fragment\n",
                __func__, __LINE__);
        }
        return 0;
    }

    dtls_ctx_t *ctx = dtls_lookup_ctx(record_ptr, sess);

    int content_type = record_ptr[0];

    if( ctx == 0 )
    {
        LOGV("[%s:%u] null context, fragment type=%d of size=%d discarded\n",
            __func__, __LINE__, content_type,  record_len);
        return 0;  // ignore
    }

    uint16_t ver = get_protocol_version(record_ptr, 0, 0);

    if( ver != ((254<<8)|253) && ver != ((254<<8)|255) )
    {
        // dtls rfc4347 254.255; rfc6347 254.253;
        LOGV("[%s:%u] unknown version %x != %x\n", __func__, __LINE__,
            ver, (int)((254<<8)|255));
        e = - e_protocol_version;
        goto exit;
    }


    uint8_t *msg_ptr = record_ptr + DTLS_REC_HEADER_SIZE;
    int      msg_max = record_len - DTLS_REC_HEADER_SIZE;
    int      msg_len = msg_max;  // can be of multiple messages

    if( ctx->epoch_rx > 0 )
    {
        // decrypt playload of the record; @msg_ptr remains valid
        msg_len = dtls_decrypt_message(ctx, (void*)record_ptr);
        if( msg_len < 0 )
        {
            LOGI("[%s:%u] PANIC: decrypt error\n", __func__, __LINE__);
            e = - e_decrypt_error;
            goto exit;
        }
    }

message_entry:

    switch( content_type )
    {
    case e_change_cipher_spec:
        e = change_cipher_spec(ctx, (void*)msg_ptr, msg_len);
        break;
    case e_alert:
        e = alert_received(ctx, (void*)msg_ptr, msg_len);
        break;
    case e_handshake:
        e = dtls_handshake(ctx, (void*)msg_ptr, msg_len);
        break;
    case e_application_data:
        e = sctp_rx(ctx, msg_ptr, msg_len);
        if( e >= 0 ) e = msg_len;
        if( e == -1 )
        {
            // e_type_abort
            ice_halt_session(sess);
            e = 0;
        }
        break;
    default:
        e = -e_unexpected_message;
        LOGV("[%s:%u] e_unexpected_message=%d\n", __func__, __LINE__, e);
        break;
    }

    if( e > 0 )
    {
        // advance record sequence number
        ctx->sequence_rx += 1;

        msg_ptr += e;
        msg_len -= e;
        if( msg_len > 0 ) goto message_entry;

        record_ptr += record_len;
        record_max -= record_len;

        if( record_max > 0 ) goto record_entry;
    }

exit:

    if( e < 0 )
    {
	    LOGI("[%s:%u] send alert code %d\n",  __func__, __LINE__, -e);
        //
        dtls_send_alert(ctx, - e);  // @e is negative
        dtls_send_alert(ctx, e_close_notify);
    }

    return 0;
}

////////////////////////////////////////////////////////////////////////////////

static int dtls_set_record(dtls_ctx_t *dtls_ctx, int type, int size)
{
    // follow rfc6347 4.1. record layer
    // content-type
    dtls_ctx->rechdr.content_type = type;
    // protocol version - rfc6347 sec 4.1. vs dtls_server_version
    dtls_ctx->rechdr.protocol_version[0] = dtl_server_version[0];
    dtls_ctx->rechdr.protocol_version[1] = dtl_server_version[1];
    // epoch
    V2_TO_BE(dtls_ctx->epoch_tx, dtls_ctx->rechdr.epoch);
    // sequence high 16-bits
    V2_TO_BE(0, dtls_ctx->rechdr.sequence_number);
    // sequence low 32-bits
    V4_TO_BE(dtls_ctx->sequence_tx, dtls_ctx->rechdr.sequence_number+2);
    // length
    V2_TO_BE(size, dtls_ctx->rechdr.length);

    // increment tx sequence number
    dtls_ctx->sequence_tx += 1;

    return (int)sizeof(dtls_ctx->rechdr);
}

static int dtls_tx_handshake(dtls_ctx_t *dtls_ctx, void *data, int size)
{
    dtls_set_record(dtls_ctx, e_handshake, size);

    return ice_send_rec(dtls_ctx->ice_session, dtls_ctx->record, data, size);
}

// (1) rfc8446 sec 4.1.3.
// struct {
//    ProtocolVersion legacy_version = 0x0303;
//    Random random;
//    opaque legacy_session_id_echo<0..32>;
//    CipherSuite cipher_suite;
//    uint8 legacy_compression_method = 0;
//    Extension extensions<6..2^16-1>;
// } ServerHello
//
static int  accept_client_hello(dtls_ctx_t *dtls_ctx)
{
    struct hs_ctx_t *hs_ctx = dtls_ctx->proto_ctx;

    dtls_hello_t *ch = &(hs_ctx->parsed_msg.hello);

    LOGV("[%s:%u] parsed ok=%d\n", __func__, __LINE__, ch->parsed_ok);

    if( hs_ctx->hsm_buffer != 0 || hs_ctx->hsm_maxlen != 0 || hs_ctx->hsm_length != 0 )
    {
        LOGI("[%s:%u] panic! %p %d %d\n", __func__, __LINE__,
            hs_ctx->hsm_buffer, hs_ctx->hsm_maxlen, hs_ctx->hsm_length);
        return -1;
    }
    hs_ctx->hsm_maxlen = HANDSHAKE_MESSAGE_MAX;
    hs_ctx->hsm_length = 0;
    hs_ctx->hsm_buffer = malloc(hs_ctx->hsm_maxlen);

    // save client hello session id
    hs_ctx->session_id.length = ch->session_id_len;
    if( ch->session_id_len > 0 )
    {
        memcpy(hs_ctx->session_id.id, ch->session_id_ptr, ch->session_id_len);
    }

    // copy assembled client hello including header
    hs_ctx->hsm_length = sizeof(dtls_handshake_t) + ch->size;
    memcpy(hs_ctx->hsm_buffer, hs_ctx->rcv_buffer, hs_ctx->hsm_length);

    // create ec key pair
    if( hs_ctx->key_pair == 0 )
    {
        hs_ctx->key_pair = init_ec_keypair();
        if( hs_ctx->key_pair == 0 )
        {
            // it takes time to cleanup stale sessions
            // just reject the connection
            LOGV("[%s:%u] init_ec_keypair() failure!\n", __func__, __LINE__);
            return -2;
        }
    }

    dtls_handshake_t * dhs;
    int pnt = 0;
#if RECORD_PER_MESSAGE
    dhs = (void*)(hs_ctx->hsm_buffer + hs_ctx->hsm_length);
    pnt = create_server_hello(dtls_ctx, dhs);
    dtls_tx_handshake(dtls_ctx, dhs, pnt);
    hs_ctx->hsm_length += pnt;

    dhs = (void*)(hs_ctx->hsm_buffer + hs_ctx->hsm_length);
    pnt = create_server_certificate(dtls_ctx, dhs);
    dtls_tx_handshake(dtls_ctx, dhs, pnt);
    hs_ctx->hsm_length += pnt;
LOGV("[%s:%u] cipher suite %.2x %.2x\n", __func__, __LINE__,
    hs_ctx->cipher_suite[0], hs_ctx->cipher_suite[1]);

    if( hs_ctx->cipher_suite[0] == s_cipher_suite[0] &&
        hs_ctx->cipher_suite[1] ==s_cipher_suite[1] )
    {
        dhs = (void*)(hs_ctx->hsm_buffer + hs_ctx->hsm_length);
        pnt = create_server_key_exchange(dtls_ctx, dhs);
        dtls_tx_handshake(dtls_ctx, dhs, pnt);
        hs_ctx->hsm_length += pnt;
    }
#if REQUEST_CLIENT_CERTIFICATE
    dhs = (void*)(hs_ctx->hsm_buffer + hs_ctx->hsm_length);
    pnt = create_certificate_request(dtls_ctx, dhs);
    dtls_tx_handshake(dtls_ctx, dhs, pnt);
    hs_ctx->hsm_length += pnt;
#endif
    dhs = (void*)(hs_ctx->hsm_buffer + hs_ctx->hsm_length);
    pnt = create_server_hello_done(dtls_ctx, dhs);
    dtls_tx_handshake(dtls_ctx, dhs, pnt);
    hs_ctx->hsm_length += pnt;

#else // RECORD_PER_MESSAGE
    dhs = (void*)(hs_ctx->hsm_buffer + hs_ctx->hsm_length + pnt);
    pnt += create_server_hello(dtls_ctx, dhs);

    dhs = (void*)(hs_ctx->hsm_buffer + hs_ctx->hsm_length + pnt);
    pnt += create_server_certificate(dtls_ctx, dhs);

    // cipher suites that requires server key exchange (RFC-5289)
    if( hs_ctx->cipher_suite[0] == s_cipher_suite[0] &&
        hs_ctx->cipher_suite[1] == s_cipher_suite[1] )
    {
        dhs = (void*)(hs_ctx->hsm_buffer + hs_ctx->hsm_length + pnt);
        pnt += create_server_key_exchange(dtls_ctx, dhs);
    }
#if REQUEST_CLIENT_CERTIFICATE
    dhs = (void*)(hs_ctx->hsm_buffer + hs_ctx->hsm_length + pnt);
    pnt += create_certificate_request(dtls_ctx, dhs);
#endif
    dhs = (void*)(hs_ctx->hsm_buffer + hs_ctx->hsm_length + pnt);
    pnt += create_server_hello_done(dtls_ctx, dhs);

    // send it - assuming @pnt bytes fit into one datagram
    dtls_tx_handshake(dtls_ctx, hs_ctx->hsm_buffer + hs_ctx->hsm_length, pnt);

    // update conversation buffer length
    hs_ctx->hsm_length += pnt;
#endif // RECORD_PER_MESSAGE

    // expect next message to be client key exchange
#if REQUEST_CLIENT_CERTIFICATE
    hs_ctx->expected_msg_type = e_certificate;
#else
    hs_ctx->expected_msg_type = e_client_key_exchange;
#endif
    return 0;  // no reply
}

//
// return encrypted block size
//
static int dtls_encrypt_message(dtls_ctx_t *ctx, dtls_rechdr_t *rechdr)
{
      uint8_t *payload = (void*)(rechdr + 1);

    // gcm nonce from rfc5288
    struct {
        uint8_t salt[TLS_FIXED_IV_LENGTH]; // 4 bytes
        uint8_t nonce_explicit[TLS_RECORD_IV_LENGTH]; // 8 bytes
    } gcm_nonce={(0)};

    // rfc5288 section 3.0
    memcpy(gcm_nonce.salt,
           ctx->dtls_key_block.server_write_IV, TLS_FIXED_IV_LENGTH);
    // rfc6655 section section 3.
    memcpy(gcm_nonce.nonce_explicit, rechdr->epoch, TLS_RECORD_IV_LENGTH);

    // aad from rfc5246
    struct {
        uint8_t  seq_num[8]; // record epoch + sequence_number
        uint8_t  type; // 22
        uint8_t  version[2];
        uint8_t  length[2];
    } additional_data={(0)};

    memcpy(additional_data.seq_num, rechdr->epoch, TLS_RECORD_IV_LENGTH);
    additional_data.type = rechdr->content_type;
    additional_data.version[0] = rechdr->protocol_version[0];
    additional_data.version[1] = rechdr->protocol_version[1];
    additional_data.length[0] = rechdr->length[0];
    additional_data.length[1] = rechdr->length[1];

    aes_parms_t *parms = __builtin_alloca(sizeof(aes_parms_t));
    memset(parms, 0, sizeof(aes_parms_t));

    parms->plaintext_ptr = (void*)payload;
    parms->plaintext_len = BE2_TO_HOST(rechdr->length);

    parms->iv_ptr = (void*)&gcm_nonce;
    parms->iv_len = sizeof(gcm_nonce);

    parms->aad_ptr = (void*)&additional_data;
    parms->aad_len = sizeof(additional_data);

    parms->key_ptr = ctx->dtls_key_block.server_write_key;

    int aead_len = TLS_RECORD_IV_LENGTH +
                   parms->plaintext_len + TLS_GCM_TAG_LENGTH;

    uint8_t *aead_ptr = __builtin_alloca(aead_len);

    memset(aead_ptr, 0, aead_len);

    parms->ciphertext_ptr = aead_ptr + TLS_RECORD_IV_LENGTH;
    parms->ciphertext_len = 0;  // not in use

    // tag at the tail
    parms->tag_ptr = aead_ptr + aead_len - TLS_GCM_TAG_LENGTH;

    int len = gcm_128_encrypt(parms);

    if( len ==  parms->plaintext_len )
    {
        // copy explict nonce
        memcpy(aead_ptr, gcm_nonce.nonce_explicit, TLS_RECORD_IV_LENGTH);

//LOGV("[%s:%u] encrypted len=%d\n", __func__, __LINE__, aead_len);
//dump_hex(aead_ptr, aead_len);

        memcpy(payload, aead_ptr, aead_len);

        // update record length
        V2_TO_BE(aead_len, rechdr->length);
    }
    else
    {
        len = 0;  // decryption failed
    }
//LOGV("[%s:%u] encrypted len=%d\n", __func__, __LINE__, aead_len);
    // return number of byte consumed
    return len > 0 ? aead_len : 0;
}

int  accept_client_finished(dtls_ctx_t *dtls_ctx)
{
    struct hs_ctx_t *hs_ctx = dtls_ctx->proto_ctx;

    int pnt = 0;

    uint8_t *record_ptr = hs_ctx->hsm_buffer + hs_ctx->hsm_length;

    // change cipher suite
    pnt = dtls_set_record(dtls_ctx, e_change_cipher_spec, 1);
    dtls_rechdr_t *rechdr = (void*)record_ptr;
    *rechdr = dtls_ctx->rechdr;
    record_ptr[pnt++] = 0x01; // rfc5246 7.1. change_cipher_spec(1)

    // new epoch
    dtls_ctx->epoch_tx += 1;
    dtls_ctx->sequence_tx = 0;

    // server finished
    rechdr = (void*)(record_ptr + pnt);

    int dhs_len = sizeof(dtls_handshake_t) + VERIFY_DATA_LENGTH;

    pnt += dtls_set_record(dtls_ctx, e_handshake, dhs_len);
    *rechdr = dtls_ctx->rechdr;

    dtls_handshake_t * dhs_ptr = (void*)(rechdr + 1); //

    memset(dhs_ptr, 0, sizeof(dtls_handshake_t));
    // fill in handshake message header
    dhs_ptr->msg_type = e_finished;
    V2_TO_BE(hs_ctx->snd_seqnum, dhs_ptr->message_seq);
    hs_ctx->snd_seqnum += 1; // increment message sequence number
    V3_TO_BE(VERIFY_DATA_LENGTH, dhs_ptr->length);
    V3_TO_BE(VERIFY_DATA_LENGTH, dhs_ptr->fragment_length);

    // fill in handshake message body

    // calculate "verify_data" rfc5246 7.4.9.
    uint8_t *verify_data = dhs_ptr->fragment_data;
    uint8_t *label_seed = __builtin_alloca(64);
    // rfc5246 7.4.9. "server finished"
    int ls_len = sprintf((char*)label_seed, "server finished");
    // SHA256_DIGEST_LENGTH=32
    hash_sha256_array(label_seed + ls_len,
                      hs_ctx->hsm_buffer, hs_ctx->hsm_length);
    ls_len += SHA256_DIGEST_LENGTH;

    int e = PRF(hs_ctx->master_secret, sizeof(hs_ctx->master_secret),
                label_seed, ls_len,
                verify_data, VERIFY_DATA_LENGTH);

    e = dtls_encrypt_message(dtls_ctx, rechdr);

    if( e > 0 )
    {
        pnt += e;
        // send it out
        ice_send_pkt(dtls_ctx->ice_session, record_ptr, pnt);
#ifdef DTLS_SRTP_OFF
  LOGV("[%s:%u] DTLS_SRTP_OFF: ice_source_srtp disabled\n", __func__, __LINE__);
#else
        ice_source_srtp(dtls_ctx->ice_session);
#endif
    }
    else
    {
        LOGV("[%s:%u] PANIC: server finished %d\n", __func__, __LINE__, e);
        e = -3;
    }

    // send encrypted server finished
    return e >= 0 ? 0 : e;
}

//
// create server hello at @dhs
//
static int  create_server_hello(dtls_ctx_t *dtls_ctx, dtls_handshake_t *dhs)
{
    struct hs_ctx_t *hs_ctx = dtls_ctx->proto_ctx;

    // generate random
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    V4_TO_BE((unsigned int)ts.tv_sec, &(hs_ctx->server_random.gmt_unix_time));

    uint64_t r = randk();
    memcpy(hs_ctx->server_random.random_bytes + 0, &r, 4);
    r = randk();
    memcpy(hs_ctx->server_random.random_bytes + 4, &r, 8);
    r = randk();
    memcpy(hs_ctx->server_random.random_bytes + 12, &r, 8);
    r = randk();
    memcpy(hs_ctx->server_random.random_bytes + 20, &r, 8);

    // handshake message header + server hello
    memset(dhs, 0, sizeof(dtls_handshake_t));
    dhs->msg_type = e_server_hello;
    V2_TO_BE(hs_ctx->snd_seqnum, dhs->message_seq);
    hs_ctx->snd_seqnum += 1; // increment message sequence number
    // rfc5246 7.4.1.3.
    uint8_t *server_hello=dhs->fragment_data;
    int      len=0;

    // server_version 254.253 rfc6437 4.2.1.
    ((tls_protocol_version_t*)(server_hello+len))->major = dtl_server_version[0];
    ((tls_protocol_version_t*)(server_hello+len))->minor = dtl_server_version[1];
    len += 2;

    // random;
    memcpy(server_hello+len, &hs_ctx->server_random, sizeof(tls_random_t));
    len += sizeof(tls_random_t);

    // session id - null id (no session resumption)
    server_hello[len++] = 0;

    // cipher_suite
    server_hello[len++] = hs_ctx->cipher_suite[0];
    server_hello[len++] = hs_ctx->cipher_suite[1];

    // compression_method - null compression
    server_hello[len++] = 0; // cpmpression method null

    // extension
    uint8_t *ext = server_hello+len+2;
    int eln = 0;
#if EXTENSION_RFC7627
    if( hs_ctx->hs_rfc7627 > 0 )
    {
        // extended master secret
        V2_TO_BE(23, ext+eln); // 0x0017
        eln += 2;
        V2_TO_BE(0, ext+eln); // length=0
        eln += 2;
    }
#endif
#if 0 // RFC-8827 (6.5.)
    // renegotiation info
    V2_TO_BE(0xff01, ext+eln); // 0xff01
    eln += 2;
    V2_TO_BE(1, ext+eln); // length=1
    eln += 2;
    ext[eln++] = 0;       // value=0
    // ec point formats
    V2_TO_BE(11, ext+eln); // 0x000b
    eln += 2;
    V2_TO_BE(2, ext+eln); // length=2
    eln += 2;
    ext[eln++] = 1;       // formats length=1
    ext[eln++] = 0;       // entry value=0 (uncompressed)
#endif
#if EXTENSION_RFC5077
    if( hs_ctx->hs_rfc5077 > 0 )
    {
        // SessionTicket TLD
        V2_TO_BE(35, ext+eln); // 0x0023
        eln += 2;
        V2_TO_BE(0, ext+eln); // length=0
        eln += 2;
    }
#endif

#if EXTENSION_SIGNATURE_ALGORITHMS
    // rfc5246 7.4.1.4. TYPE_SIGNATURE_ALGORITHMS
    V2_TO_BE(TYPE_SIGNATURE_ALGORITHMS, ext+eln);
    eln += 2;
    V2_TO_BE(6, ext+eln); // rfc5246 7.4.1.4.
    eln += 2;
    V2_TO_BE(4, ext+eln); // rfc5246 7.4.1.4.1. supported_signature_algorithms
    eln += 2;
    ext[eln++] = hs_ctx->hash_signature[0];
    ext[eln++] = hs_ctx->hash_signature[1];
    ext[eln++] = 0x04; // sha256
    ext[eln++] = 0x03; // ecdsa
#endif
    // TYPE_USE_SRTP  rfc5764 (4.1.1.)
    V2_TO_BE(TYPE_USE_SRTP, ext+eln);
    eln += 2;
    V2_TO_BE(5, ext+eln); // rfc5246 7.4.1.4. one element of 4 bytes
    eln += 2;
    V2_TO_BE(2, ext+eln); // one srtp profile
    eln += 2;
    ext[eln++] = hs_ctx->srtp_profile[0];
    ext[eln++] = hs_ctx->srtp_profile[1];
    // no mki
    ext[eln++] = 0;

    // extension size
    V2_TO_BE(eln, server_hello+len);

    len += (2 + eln);

    // set message length and fragment length
    V3_TO_BE(len, dhs->length);
    V3_TO_BE(len, dhs->fragment_length);
//dump_hex(server_hello, len);
//LOGV("[%s:%u] len=%d\n", __func__, __LINE__, len);

    return sizeof(dtls_handshake_t) + len;
}

extern void *session_x509_ctx(void *sess);

//
// create server certificate at @dhs
//
static int  create_server_certificate(dtls_ctx_t *dtls_ctx, dtls_handshake_t *dhs)
{
    struct hs_ctx_t *hs_ctx = dtls_ctx->proto_ctx;
    // handshake message header
    memset(dhs, 0, sizeof(dtls_handshake_t));
    dhs->msg_type = e_certificate;
    V2_TO_BE(hs_ctx->snd_seqnum, dhs->message_seq);
    hs_ctx->snd_seqnum += 1; // increment message sequence number

    // certificate list - rfc5246 (7.4.2.)
    uint8_t *cert=dhs->fragment_data;
    int      len=0;

    void *x509_ctx = session_x509_ctx(dtls_ctx->ice_session);
    LOGV("[%s:%u] x509=%p\n", __func__, __LINE__, x509_ctx);
    // (1) size of the list of certificates (in bytes)
    // (2) size if the certificate in bytes
    // (3) certificate
    len = der_x509_certificate(x509_ctx, cert+6, 2048);
    V3_TO_BE(len, cert+3); // size of the certificate
    len += 3; // size of the first element of the list
    V3_TO_BE(len, cert);  // size of the whole list
    len += 3;
    V3_TO_BE(len, dhs->length); // size of the message
    V3_TO_BE(len, dhs->fragment_length);
//dump_hex(cert, len);
//LOGV("[%s:%u] len=%d\n", __func__, __LINE__, len);

    return sizeof(dtls_handshake_t) + len;
}

//
// server_key_exchange needed for ECDHE_ECDSA, ECDHE_RSA as per rfc4492
// supported cipher suites:
// TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
//
static int  create_server_key_exchange(dtls_ctx_t *dtls_ctx, dtls_handshake_t *dhs)
{
    struct hs_ctx_t *hs_ctx = dtls_ctx->proto_ctx;

    // handshake message header
    memset(dhs, 0, sizeof(dtls_handshake_t));
    dhs->msg_type = e_server_key_exchange;
    V2_TO_BE(hs_ctx->snd_seqnum, dhs->message_seq);
    hs_ctx->snd_seqnum += 1; // increment message sequence number

    // ECDHE server params - rfc5246 (7.4.4.)
    uint8_t *parms=dhs->fragment_data;
    int      len=0;

    // ECCurveType: named_curve (3)
    parms[len++] = e_named_curve;
    // secp256r1==0x0017
    int named_curve = get_curved_name(hs_ctx->key_pair);
    V2_TO_BE(named_curve, parms + len);
    len += 2;
    // ECPoint: public_key max size 255 bytes
    int n = copy_ec_pub_key(hs_ctx->key_pair, parms+len+1, 256); //
    parms[len] = (unsigned char)n;
    len += (1 + n);

    // signed_params

    void *x509_ctx = session_x509_ctx(dtls_ctx->ice_session);
    struct iovec in[4]={(0)};

    in[0].iov_base = &(hs_ctx->client_random);  // client random
    in[0].iov_len = sizeof(tls_random_t);
    in[1].iov_base = &(hs_ctx->server_random);  // server random
    in[1].iov_len = sizeof(tls_random_t);
    in[2].iov_base= parms;  // params
    in[2].iov_len = len;    // length of params

    // set signature algorithm - 0x0401 for rsa_pkcs1_sha256
    parms[len++] = hs_ctx->hash_signature[0];
    parms[len++] = hs_ctx->hash_signature[1];

    int ds_len = sign_with_x509(x509_ctx, parms+len+2, 256, in);

    // set digital signature length
    V2_TO_BE(ds_len, parms + len);

    len += (2 + ds_len);

    // fragment header
    V3_TO_BE(len, dhs->length); // size of the message
    V3_TO_BE(len, dhs->fragment_length);

//dump_hex(parms, len);

    return sizeof(dtls_handshake_t) + len;
}

#if REQUEST_CLIENT_CERTIFICATE
//
// create certificate request at @dhs
//
static int  create_certificate_request(dtls_ctx_t *dtls_ctx, dtls_handshake_t *dhs)
{
    struct hs_ctx_t *hs_ctx = dtls_ctx->proto_ctx;

    // handshake message header
    memset(dhs, 0, sizeof(dtls_handshake_t));
    dhs->msg_type = e_certificate_request;
    V2_TO_BE(hs_ctx->snd_seqnum, dhs->message_seq);
    hs_ctx->snd_seqnum += 1; // increment message sequence number

    // certificate list - rfc5246 (7.4.4.)
    uint8_t *req=dhs->fragment_data;
    int      len=0;

    // certificate_types
    req[len++] = 2; // 1 certificate_types
    req[len++] = e_rsa_sign;
    req[len++] = e_ecdsa_sign; //e_rsa_fixed_dh;
    // use rfc5246 tls 1.2 v.s. rfc2246 tls 1.0
    if( dtl_server_version[1] == 253 )
    {
        // supported_signature_algorithms
        V2_TO_BE(4, req+len);
        len += 2;
        req[len++] = 0x04; // 0x0403 = ECDSA SHA256 ecdsa_secp256r1_sha256
        req[len++] = 0x03; // ECDSA
        req[len++] = 0x04; // SHA256
        req[len++] = 0x01; // RSA
    }
    // certificate_authorities - null
    V2_TO_BE(0, req+len);  // size of the list to follow
    len += 2;

    // fragment header
    V3_TO_BE(len, dhs->length);
    V3_TO_BE(len, dhs->fragment_length);
dump_hex(req, len);
LOGV("[%s:%u] len=%d\n", __func__, __LINE__, len);

    return sizeof(dtls_handshake_t) + len;
}
#endif // REQUEST_CLIENT_CERTIFICATE

//
// create server hello done at @dhs
//
static int  create_server_hello_done(dtls_ctx_t *dtls_ctx, dtls_handshake_t *dhs)
{
    struct hs_ctx_t *hs_ctx = dtls_ctx->proto_ctx;

    // handshake message header
    memset(dhs, 0, sizeof(dtls_handshake_t));
    dhs->msg_type = e_server_hello_done;
    V2_TO_BE(hs_ctx->snd_seqnum, dhs->message_seq);
    hs_ctx->snd_seqnum += 1; // increment message sequence number

    // certificate list - rfc5246 (7.4.5.)
    int      len=0;

    // null message body

    // fragment header
    V3_TO_BE(len, dhs->length);
    V3_TO_BE(len, dhs->fragment_length);

    return sizeof(dtls_handshake_t) + len;
}

#if EXTENSION_RFC5077
static int  create_session_ticket(dtls_ctx_t *dtls_ctx, dtls_handshake_t *dhs)
{
    struct hs_ctx_t *hs_ctx = dtls_ctx->proto_ctx;

    // handshake message header
    memset(dhs, 0, sizeof(dtls_handshake_t));
    dhs->msg_type = e_session_ticket;
    V2_TO_BE(hs_ctx->snd_seqnum, dhs->message_seq);
    hs_ctx->snd_seqnum += 1; // increment message sequence number

    // certificate list - rfc5246 (7.4.5.)
    uint8_t *txt=dhs->fragment_data;
    int      len=0;

    // ticket_lifetime_hint
    V4_TO_BE(7200, txt+len);
    len += 4;
    V2_TO_BE(128, txt+len);
    len += 2;
    memset(txt+len, 'g', 128);
    len += 128;

    // fragment header
    V3_TO_BE(len, dhs->length);
    V3_TO_BE(len, dhs->fragment_length);

    return sizeof(dtls_handshake_t) + len;
}
#endif

////////////////////////////////////////////////////////////////////////////////

//
// free up srtp crypto context
//
void  dtls_close_srtp(void *sess)
{
    void **srtp_crypt = get_srtp_cryptos(sess);

    if( srtp_crypt[0] )
    {
        free_srtp_crypt(srtp_crypt[0]);
    }

    if( srtp_crypt[1] )
    {
        free_srtp_crypt(srtp_crypt[1]);
    }
    set_srtp_cryptos(sess, 0, 0);
}

//
// set up srtp crypto context
//
void  dtls_setup_srtp(dtls_ctx_t *dtls_ctx)
{
    struct srtp_key_block_t *key_block = &(dtls_ctx->srtp_key_block);

    void *tx_crypt = 0;
    void *rx_crypt = 0;

    tx_crypt = init_srtp_crypt(key_block->server_write_SRTP_master_key,
                            SRTP_MASTER_KEY_LENGTH,
                            key_block->server_write_SRTP_master_salt);

    rx_crypt = init_srtp_crypt(key_block->client_write_SRTP_master_key,
                            SRTP_MASTER_KEY_LENGTH,
                            key_block->client_write_SRTP_master_salt);

    set_srtp_cryptos(dtls_ctx->ice_session, tx_crypt, rx_crypt);
}

void *dtls_get_sctp(void *ctx)
{
    return ((dtls_ctx_t*)ctx)->sctp_tcb;
}

void  dtls_set_sctp(void *ctx, void *sctp_tcb)
{
    dtls_ctx_t *dtls_ctx = ctx;

    if( dtls_ctx ) dtls_ctx->sctp_tcb = sctp_tcb;
}

// send sctp packet over dtls session
int   dtls_tx_userdata(void *ctx, void *data, int size)
{
    dtls_ctx_t *dtls_ctx = ctx;
    // use hs_ctx tx buffer
    struct hs_ctx_t *hs_ctx = dtls_ctx->proto_ctx;

    int pnt = 0;

    uint8_t *record_ptr = hs_ctx->hsm_buffer + hs_ctx->hsm_length;

    pnt = dtls_set_record(ctx, e_application_data, size);
    // set tx buffer record header
    *(dtls_rechdr_t*)record_ptr = dtls_ctx->rechdr;
    // copy tx data
    __builtin_memcpy(record_ptr+pnt, data, size);

    int e = dtls_encrypt_message(dtls_ctx, (dtls_rechdr_t*)record_ptr);
    if(e >= 0)
    {
        pnt += e; // add encrypted size
//        LOGV("[%s:%u] size=%d\n", __func__, __LINE__, pnt);
//        dump_hex(record_ptr, pnt);
        //
        // send it out
        ice_send_pkt(dtls_ctx->ice_session, record_ptr, pnt);
    }
    else
    {
        LOGI("[%s:%u] WARNING: dtls_encrypt_message=%d\n", __func__, __LINE__, e);
    }

    return e >= 0 ? size : 0;
}

void *dtls_ice_session(void *ctx)
{
    return ((dtls_ctx_t*)ctx)->ice_session;
}
