// file : sipagent.c
// date : 12/26/2019
//
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <poll.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <pthread.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/sendfile.h>
#include <sys/ioctl.h>

#include "cryptlib/prng.h"
#include "cryptlib/sha1.h"
#include "cryptlib/base64.h"
#include "x509cert.h"
#include "stun5389.h"
#include "mediartp.h"

#define LOGV(...)
//#define LOGI(...)
//#define LOGV printf
#define LOGI printf

enum e_wrdr {
    e_recvonly=1,
    e_sendlony,
    e_sendrecv,
    e_wrdr_max,
};

enum e_transport {
    e_transport_udp=1,
    e_transport_tcp,
    e_transport_max
};

enum e_candidate_type
{
    e_candidate_host=1,
    e_candidate_srflx,
    e_candidate_prflx,
    e_candidate_relay,
    e_candidate_max
};

#define DO_ICE_TRICKLE

#define SIP_MAX_RETENTION   300  // seconds
#define SIP_MAX_USERS       16

typedef struct peer_t
{
    // rfc5245, draft-ietf-mmusic-ice-sip-sdp
    uint8_t        foundation[32]; // up to 32 characters
    struct in_addr ipv4;      // candidate ipv4
    uint16_t       port;      // candidate port host-order
    uint16_t       component_id; // up to (5)/(3) digits
    int            transport; // enum e_transport
    uint32_t       priority;  // up to 10 digits
    int            candidate_type; // e_candidate_type

    char           ice_ufrag[256]; // peer username >= 24 bits
    char           ice_pwd[256];   // peer password >= 128 bits
    int            fp_length;        // fingerprint length
    uint8_t        fingerprint[32];  // fingerprint
    char           algo[16];  // fingerprint algo e.g. sha-256

    struct in_addr sipv4;      // candidate srflx ipv4
    uint16_t       sport;      // candidate srflx port host-order

    int            rdwr;      // enum e_wrdr
    uint32_t       ssrc;

}    peer_t;

// sip agent context
typedef struct sipx_t
{
    pthread_mutex_t  lock;

    void  *ice_ctx;

    struct pair_t {

        void      *ice_session;

        int32_t    last_heard;   // last heard, utc seconds

        char       host_ice_ufrag[32];
        char       host_ice_pwd[32];

        // local host address is obtained ice_get_candidates()

        struct in_addr sipv4;    // candidate srflx ipv4
        uint16_t       sport;    // candidate srflx port host-order
        int            stun_id;  // stun server index to use

        peer_t     peer;

        void      *sctx;  // sip negotiation phase

    }   pair[SIP_MAX_USERS];

}   sipx_t;

typedef struct sctx_t
{
    sipx_t *sipx;
    char   *mime; // content-type/content-disposition
    struct sockaddr_in sa;
    int  *fd;     // pointer to client socket
    int   state;
    int   rtc;
    int   len;
    int   max;
    char *buf;
}   sctx_t;

static int32_t sip_atoi32(char *ptr, int len)
{
    int sign = 1;
    int n = 0;
    
    if( *ptr == '-' ) { sign = -1; ptr++;}
    else if( *ptr == '+' ) ptr++;
    
    for(; *ptr; ptr += 1)
    {
        if( *ptr == ',') continue;
        if( ! isdigit(*ptr) ) break;
        n = n*10 + *ptr-'0';
    }
    
    return sign * n;
}

extern int  * ice_quit_pointer(void *icex);
extern void * session_x509_ctx(void *sess);

extern int    ws_send_message(sctx_t *sctx, char *msg, int len);
extern int    ice_session_port(void *sess);
extern void * ice_session_peer(void *sess);
extern void * ice_open_session(void *icex);
extern int    ice_get_candidates(void *sess, char *str, int len);
extern int    ice_send_msg(void *sess, struct sockaddr_in *to, uint8_t *msg, int len);

extern int    ice_query_srflx(void *sess, int stun_index);
extern void   ice_stun_rotate(int index_next);

// return utc seconds
static int32_t sip_utc_time(void)
{
    struct timespec  tv;
    clock_gettime(CLOCK_REALTIME, &tv);
    
    return (int32_t)(tv.tv_sec);
}

static sipx_t g_ctx[1] =
{
    { .lock = PTHREAD_MUTEX_INITIALIZER}
};

//
// stun server calls sip_query_user() to retrieve ice_pwd for
// message integrity check. this is feasible because ice_ufrag is
// created specific to a session in sip_assign_pair()
// a side-effect is to record peer ice_ufrag in stun binding request
// to match future sdp put from client
//
void * sip_query_ufrag(char *name, int len)
{
    sipx_t *sipx = g_ctx + 0;

    struct pair_t *pair;
    int j;
    for(j = 0, pair=sipx->pair; j < SIP_MAX_USERS; j++, pair++)
    {
        if( pair->ice_session == 0 ) continue;

        int  k;
        // search for separator :
        for( k = 0; k < len && name[k] !=':'; k++);

        if( k == 0 || k == len ) continue;

#ifdef SIP_MATCH_PEER_NAME // undefined
        if( strlen(pair->peer.ice_ufrag) == len-k &&
            0 == memcmp(pair->peer.ice_ufrag, name, len-k) )
        {
            return pair->host_ice_pwd;
        }
#else // match self-name ok with rfc 8445 sec 7.3
        if( strlen((char*)pair->host_ice_ufrag) == k &&
            0 == memcmp(pair->host_ice_ufrag, name, k) )
        {
            // side-effect: save peer ice-ufrag
            strcpy(pair->peer.ice_ufrag, name+k+1);

            return pair->host_ice_pwd;
        }
#endif
    }

    return 0;
}

//
// when ice sesseion concludes, iceagent should call sip_remove_pair()
// to free up sip session context
//
void   sip_release_pair(void *ice_session)
{
    sipx_t *sipx = g_ctx + 0;

    pthread_mutex_lock(&sipx->lock);

    struct pair_t *pair;
    int j;
    for(j = 0, pair=sipx->pair; j < SIP_MAX_USERS; j++, pair++)
    {
        if( pair->ice_session == ice_session )
        {
            pair->sctx = 0;
            pair->ice_session = 0;
            break;
        }
    }
    if( j < SIP_MAX_USERS )
    {
        LOGV("[%s:%u] remove ice peer %s:%u\n", __func__, __LINE__,
            inet_ntoa(pair->peer.ipv4), pair->peer.port);
    }
    pthread_mutex_unlock(&sipx->lock);
}

#ifdef DO_ICE_TRICKLE
// send stun message to an ice candidate
static int stun_candidate(void *ice_session, peer_t *peer)
{
    if( e_transport_udp != peer->transport )
    {
        return 0;
    }
    if( 0 == peer->ipv4.s_addr)
    {
        return 0;
    }
    uint8_t msg[STUN_MSG_MAX];
    // use e_stun_class_inidication to open NAT
    int len = create_stun_message(msg, STUN_MSG_MAX, e_stun_class_inidication, 0);
    // send a udp packet to open firewall port
    struct sockaddr_in to={(0)};
    to.sin_family = AF_INET;
    to.sin_addr = peer->ipv4;
    to.sin_port = htons(peer->port);

    len = ice_send_msg(ice_session, &to, msg, len);

     LOGV("[%s:%u] sent %d bytes to %s:%u\n", __func__, __LINE__, len,
            inet_ntoa(peer->ipv4), peer->port);
    return len;
}
#endif // DO_ICE_TRICKLE
//
// sip_update_peer() is called when a sdp put command is processed
// in the case of firefox, this is called after stun binding request
// and dtls handshake. in that case, the corresponding ice session
// has already recorded peer source address so the session can be matched
// with the candidate information contained in the incoming sdp
// however, the timeline appears not to be a requirement so it is possible
// to have sdp put before any peer source information. in that case source
// matching will fail - but in the case of sendonly media, this appears
// not to be a problem
//
static int sip_update_peer(sipx_t *sipx, peer_t *peer)
{
    pthread_mutex_lock(&sipx->lock);

    int j;
    for(j = 0; j < SIP_MAX_USERS; j++)
    {
        if( 0 == sipx->pair[j].ice_session ) continue;

        // match ice ufrag
        if( 0 == strcmp(sipx->pair[j].peer.ice_ufrag, peer->ice_ufrag) )
        {
            break;
        }
        // match peer source address to ice sessions
        struct sockaddr_in *from = ice_session_peer(sipx->pair[j].ice_session);
        if( peer->candidate_type == e_candidate_host  &&
            peer->port == ntohs(from->sin_port) &&
            peer->ipv4.s_addr == from->sin_addr.s_addr )
        {
            break;
        }
        // check hit time within 2 seconds
        if( (int)sip_utc_time() - (int)sipx->pair[j].last_heard < 2 )
        {
            LOGV("[%s:%u] update ice peer %s from %s:%u\n", __func__, __LINE__,
                peer->ice_ufrag, inet_ntoa(peer->ipv4), peer->port);
            break;
        }
    }

    if( j < SIP_MAX_USERS )
    {
        sipx->pair[j].peer = *peer;
        sipx->pair[j].last_heard = sip_utc_time();

        LOGV("[%s:%u] update ice peer %s from %s:%u\n", __func__, __LINE__,
           peer->ice_ufrag, inet_ntoa(peer->ipv4), peer->port);
#ifdef DO_ICE_TRICKLE
        stun_candidate(sipx->pair[j].ice_session, peer);
#endif
    }
    else
    {
        LOGV("[%s:%u] no matching ice session from %s:%u\n", __func__, __LINE__,
           inet_ntoa(peer->ipv4), peer->port);
    }

    pthread_mutex_unlock(&sipx->lock);
    
    return (j < SIP_MAX_USERS ? 0 : -1);
}

#define IS_CRLF(c) ((c)=='\r'||(c)=='\n')

static int get_next_line(char *para, int size, int *pos)
{
    int i, j;

    // skip leading crlf
    for(i = *pos; i < size && IS_CRLF(para[i]); i++);
    
    if( i >= size ) return -1; // end of lines

    // scan to trailing crlf
    for(j = i; j < size && (!IS_CRLF(para[j])); j++);
    
    *pos = i;

    return j-i;
}

#if 0
// match a line of @lead from @para + @off[0]; return line length
static int get_match_line(char *lead, char *para, int size, int *off)
{
    int n, k;
    int llen = 0;
    if( lead ) llen = strlen(lead);
    
    for(k=0; 0 < (n = get_next_line(para, size, &k)); k +=n )
    {
        char *line = para+k;
        
        if( llen ==0 || 
            (n >= llen && 0 ==strncasecmp(lead, line, llen)) )
        {
            if( off ) *off = k;
            
            return n;
        }
    }
    return -1;  // no match
}
#endif

#define IS_WHITESPACE(c) ((c)==' '||(c)=='\t')

static int get_next_word(char *line, int size, int *pos)
{
    int i, j;

    // skip leading whitespaces
    for(i = *pos; i < size && IS_WHITESPACE(line[i]); i++);
    
    if( i >= size ) return -1; // end of lines

    // scan to trailing whitespaces
    for(j = i; j < size && (!IS_WHITESPACE(line[j])); j++);
    
    *pos = i;

    return j-i;
}

// rfc5245, draft-ietf-mmusic-ice-sip-sdp
// @line starts with <foundation>
static int sdp_candidate(char *line, int size, peer_t *peer)
{
    // javascript downloaded to browser put valid
    // candidate on the first line of sdp block.
    // so ignore any candidate that's not the first line
//    if( peer->ipv4.s_addr ) return 0;

    int   off;
    int   len;

    // foundation
    off = 0;
    len = get_next_word(line, size, &off);
    if( len <= 0 ) return -1;
    if( len > sizeof(peer->foundation) ) return -2;
    memcpy(peer->foundation, line + off, len);
    
    // component-id
    off += len;
    len = get_next_word(line, size, &off);
    if( len <= 0 ) return -3;
    peer->component_id = sip_atoi32(line + off, len);

    // transport
    peer->transport = e_transport_max;
    off += len;
    len = get_next_word(line, size, &off);
    if( len <= 0 ) return -4;
    if( len != 3 || 0 != strncasecmp(line+off, "udp", 3) )
    {
        return 0; // unknown transport, ignore
    }
    peer->transport = e_transport_udp;
    
    // priority
    off += len;
    len = get_next_word(line, size, &off);
    if( len <= 0 ) return -5;
    peer->priority = sip_atoi32(line + off, len);

    // connection address
    peer->ipv4.s_addr = 0;
    off += len;
    len = get_next_word(line, size, &off);
    if( len <= 0 ) return -6;
    if( len < 16 )
    {
        char addr[16]={(0)};
        memcpy(addr, line+off, len);
        inet_pton(AF_INET, addr, &(peer->ipv4));
    }

    // port
    peer->port = 0;
    off += len;
    len = get_next_word(line, size, &off);
    if( len <= 0 ) return -7;
    peer->port = sip_atoi32(line + off, len);
    
    // candidate type
    peer->candidate_type = e_candidate_max;
    off += len;
    len = get_next_word(line, size, &off);
    if( len != 3 || strncasecmp(line+off, "typ", 3) ) return -7;
    
    off += len;
    len = get_next_word(line, size, &off);
    if( len <= 0 ) return -7;
    if( len == 4 && 0 == strncasecmp(line+off, "host", 4) )
    {
        peer->candidate_type = e_candidate_host;
    }
    else if( len == 5 && 0 == strncasecmp(line+off, "srflx", 5) )
    {
        peer->candidate_type = e_candidate_srflx;
    }
    else if( len == 5 && 0 == strncasecmp(line+off, "prflx", 5) )
    {
        peer->candidate_type = e_candidate_prflx;
    }
    else if( len == 5 && 0 == strncasecmp(line+off, "relay", 5) )
    {
        peer->candidate_type = e_candidate_relay;
    }
    else return -8;
    
    return 1;
}

// a=ice-pwd
static int sdp_password(char *line, int size, peer_t *peer)
{
    int   off;
    int   len;

    off = 0;
    len = get_next_word(line, size, &off);
    if( len <= 0 ) return -1;
    if( len >= sizeof(peer->ice_pwd) ) return -2;
    memcpy(peer->ice_pwd, line + off, len);
    
    return 0;
}

// a=ice-ufrag
static int sdp_username(char *line, int size, peer_t *peer)
{
    int   off;
    int   len;

    off = 0;
    len = get_next_word(line, size, &off);
    if( len <= 0 ) return -1;
    if( len >= sizeof(peer->ice_ufrag) ) return -2;
    memcpy(peer->ice_ufrag, line + off, len);

    return 0;
}

static int get_next_byte(char *hex, int len, int *off)
{
    int b = 0;
    
    int k=*off;
    
    if( k >= len ) return -1;  // -1 eol

    // skip 1 character separator if present
    if( hex[k] == ':' || hex[k] == ' ' || hex[k] == '-' ) k++;

    if( k >= len ) return -1;  // -1 eol

    uint8_t a = tolower(hex[k]);
    
    if( (a < '0' || a > '9') && (a < 'a' || a > 'f') ) return 256;

    b = (a >= 'a' ? 10 + a - 'a' : a - '0') << 4;

    if( ++k >= len ) return -257;  // -1 eol

    a = tolower(hex[k]);

    if( (a < '0' || a > '9') && (a < 'a' || a > 'f') )
    {
        return 258;
    }

    b += (a >= 'a' ? 10 + a - 'a' : a - '0');

    // update offset
    *off = k+1;
    
    return b;
}

//
// there can be multiple "a=fingerprint" lines in an sdp
// each will overwrite the previous one. it is assumed ther are identical
//
static int sdp_findgerprint(char *line, int size, peer_t *peer)
{
    int   off;
    int   len;

    // hash algorithm
    off = 0;
    len = get_next_word(line, size, &off);
    if( len <= 0 ) return -1;
    if( len >= sizeof(peer->algo) ) return -2;
    memcpy(peer->algo, line + off, len);

    // fingerprint
    off += len;
    int b, j=0;
    while( (b = get_next_byte(line, size, &off)) )
    {
        if( b < 0 || b > 255) break; // eol or error
        peer->fingerprint[j++] = b;
    }
    peer->fp_length = j;

    if( b > 255 ) 
    {
        LOGI("[%s:%u] b=%d\n", __func__, __LINE__, b);
        return -3;
    }
    
    return 0;
}

static void print_peer(peer_t *peer)
{
    LOGV("[%s:%u]:\n", __func__, __LINE__);
    LOGV("candidate\nfoundation=%s component-id=%u transport=%d\n"
         "priority=%u ipv4=%s port=%u candidate-type=%d\n",
         peer->foundation, peer->component_id, peer->transport,
         peer->priority, inet_ntoa(peer->ipv4), peer->port,
         peer->candidate_type);

    LOGV("ice-pwd=%s\nice-ufrag=%s\n",
         peer->ice_pwd, peer->ice_ufrag);
    
    char text[256];
    int j, k=0;
    for(j=0; j < peer->fp_length; j++)
    {
        k += sprintf(text+k, "%.2x", peer->fingerprint[j]);
    }
    LOGV("fingerprint=%s (%d)%s\n", peer->algo, peer->fp_length, text);
}

#ifdef DO_ICE_TRICKLE
static void * sip_process_ice(sctx_t *sctx, char *ice, int len)
{
    char *local_user = ice;
    peer_t *peer = __builtin_malloc(sizeof(peer_t));
    memset(peer, 0, sizeof(*peer));
    int i;
    for( i = 0; i < len && ice[i] != ' ' && ice[i] != ':'; i += 1 );
    if( ice[i] != ':' )
    {
        LOGI("[%s:%u] bad ice line: %s\n", __func__, __LINE__, ice);
        goto exit;
    }
    ice[i++] = '\0';
    int j;
    for(j = 0; j < sizeof(peer->ice_ufrag) && i < len  && ice[i] != ' '; j++, i++)
    {
        peer->ice_ufrag[j] = ice[i];
    }
    if( ice[i] != ' ' )
    {
        LOGI("[%s:%u] bad ice line: %s\n", __func__, __LINE__, ice);
        goto exit;
    }
    i += 1;
    char *key = "candidate:";
    int klen = strlen(key);
    if( 0 != strncasecmp(ice + i, key, klen) )
    {
        LOGI("[%s:%u] bad ice line: %s\n", __func__, __LINE__, ice);
        goto exit;
    }
    i += klen;
    sdp_candidate(ice + i, len - i, peer);
    // ref. sip_update_peer()
    sipx_t *sipx = sctx->sipx;
    pthread_mutex_lock(&sipx->lock);
    for(j = 0; j < SIP_MAX_USERS; j++)
    {
        if( 0 == sipx->pair[j].ice_session ) continue;
        if( strcmp(sipx->pair[j].host_ice_ufrag, local_user) ) continue;
        LOGI("[%s:%u] found local user %s\n", __func__, __LINE__, local_user);
        if( sipx->pair[j].stun_id >= 0 )
        {
            sipx->pair[j].sctx = sctx;
            sipx->pair[j].stun_id = ice_query_srflx(sipx->pair[j].ice_session,  sipx->pair[j].stun_id);
        }
        sipx->pair[j].peer = *peer;
        sipx->pair[j].last_heard = sip_utc_time();
        LOGV("[%s:%u] stun ice peer %s from %s:%u\n", __func__, __LINE__,
           peer->ice_ufrag, inet_ntoa(peer->ipv4), peer->port);
        stun_candidate(sipx->pair[j].ice_session, peer);
        break;
    }
    pthread_mutex_unlock(&sipx->lock);
exit:
    if( peer )
    {
        //sip_update_peer(sctx->sipx, peer);
        //print_peer(peer);
        __builtin_free(peer);
    }
    return 0;
}
#endif // DO_ICE_TRICKLE

// client send in sdp
static void * sip_process_sdp(sctx_t *sctx, char *sdp, int len)
{
    static struct {
        char *key;
        int (*use)(char *line, int size, peer_t *peer);
    } map[]={{"a=candidate:", 0},
             {"a=ice-pwd:", sdp_password},
             {"a=ice-ufrag:", sdp_username},
             {"a=fingerprint:", sdp_findgerprint},
             {0,0}};

    int n, k;
    peer_t *peer = __builtin_malloc(sizeof(peer_t));
    memset(peer, 0, sizeof(*peer));

    for(k=0; 0 < (n = get_next_line(sdp, len, &k)); k +=n )
    {
        char *line = sdp+k;
        int j;
        for(j=0; map[j].key && map[j].use; j++)
        {
            int klen = strlen(map[j].key);
            if( n >= klen && strncasecmp(line, map[j].key, klen)==0 )
            {
                int e = map[j].use(line+klen, n-klen, peer);
                if( 0 >  e )
                {
                    LOGI("[%s:%u] invalid (e=%d) sdp line %s\n",
                        __func__, __LINE__, e, map[j].key);
                    __builtin_free(peer);
                    peer = 0;
                    goto exit;
                }
            }
        }
    }
    map[0].use = sdp_candidate;
    for(k=0; 0 < (n = get_next_line(sdp, len, &k)); k +=n )
    {
        char *line = sdp+k;
        int j;
        for(j=0; j==0 && map[j].key && map[j].use; j++)
        {
            int klen = strlen(map[j].key);
            
            if( n >= klen && strncasecmp(line, map[j].key, klen)==0 )
            {
                int e = map[j].use(line+klen, n-klen, peer);
                if( 0 >  e )
                {
                    LOGI("[%s:%u] invalid (e=%d) sdp line %s\n",
                        __func__, __LINE__, e, map[j].key);
                    __builtin_free(peer);
                    peer = 0;
                    goto exit;
                }
                else if( e > 0 )
                {
                    sip_update_peer(sctx->sipx, peer);
                    print_peer(peer);
                }
            }
        }
    }
exit:
    if( peer )
    {
        __builtin_free(peer);
    }
    return 0;
}

/*
// ref. draft-ietf-rtcweb-jsep-?? seciton 5.2.
//      rfc8445 section 10
static char *offer_sdp_prefix=
"v=0\r\n"
"o=- 3208859441974679698 0 IN IP4 0.0.0.0\r\n"
"s=-\r\n"
"t=0 0\r\n"
"a=fingerprint:sha-256 8D:D4:F6:A2:D2:17:E4:78:28:42:BF:67:F2:EA:4F:BC:13:32:9B:C3:81:55:49:90:AC:28:2C:C6:82:C2:1A:FA\r\n"
"a=ice-options:trickle\r\n"
"a=ice-ufrag:074c6550\r\n"
"a=ice-pwd:a28a397a4c3f31747d1ee3474af08a06\r\n"
"a=ice-lite\r\n"
"a=msid-semantic:WMS *\r\n"
"a=setup:passive\n"
"a=mid:video\r\n"
"m=video 64000 UDP/TLS/RTP/SAVPF 96\r\n"
"c=IN IP4 0.0.0.0\r\n"
"b=RS:0\r\n"
"b=RR:0\r\n"
"a=rtcp-mux\r\n"
"a=rtcp-mux-only\r\n"
"a=rtpmap:96 H264/90000\r\n"
"a=fmtp:96 profile-level-id=42e01f;packetization-mode=1\r\n"
"a=sendonly\r\n"
//"a=candidate:1 1 UDP 2130706431 192.168.127.7 64000 typ host\r\n"
"";
*/
// rfc4566
//
static int make_sdp_prefix(char *sdp, int len)
{
    static uint32_t sess_id;
    static uint32_t sess_ver=0;

    if( sess_id == 0 )
    {
        sess_id = sip_utc_time();
    }
    else
    {
        sess_id += 1;
    }

    int n = snprintf(sdp, len,
              "v=0\r\n"
              "o=- %u %u IN IP4 0.0.0.0\r\n"
              "s=-\r\n"
              "t=0 0\r\n"
              "",
              sess_id, sess_ver);

    return n;
}

// rfc4572
// draft-ietf-mmusic-4572-update-
static int make_sdp_x509(struct pair_t *pair, char *sdp, int len)
{
    void *x509_ctx = session_x509_ctx(pair->ice_session);

    if( x509_ctx == 0 )
    {
        LOGV("[%s:%u] null x509 context\n", __func__, __LINE__);
        return 0;
    }

    int k = get_x509_fingerprint(x509_ctx, 0, 0);

    char *fingerprint= __builtin_alloca(k+1);

    k = get_x509_fingerprint(x509_ctx, fingerprint, k+1);

    int n = snprintf(sdp, len,
              "a=%s\r\n",
              fingerprint);

    return n;
}

// rfc5245 rfc8445
static int make_sdp_ice(struct pair_t *pair, char *sdp, int len)
{
    int n = snprintf(sdp, len,
               "a=ice-options:trickle\r\n"
               "a=ice-ufrag:%s\r\n"
               "a=ice-pwd:%s\r\n"
               "a=ice-lite\r\n"
               , pair->host_ice_ufrag, pair->host_ice_pwd);

    return n;
}

// draft-ietf-mmusic-msid
// removed ref draft-ietf-mmusic-msid-17 B.15.
static int make_sdp_msid(char *sdp, int len)
{
    int n = snprintf(sdp, len,
                "a=msid-semantic:WMS *\r\n");

    return n;
}
// rfc5245 rfc8445
// the candidate priorities: (rfc5245 sec. 4.1.2.1. and 4.1.2.2)
// type priority: 126 for host type
// local priority: (ICE_MAX_INTERFACES - j) or j
//                 where j is the index in g_ip_intf
// component ID: 1 for rtp, 2 for rtcp
static int make_srflx_candidate(struct pair_t *pair, char *str, int len)
{
	union {
		uint32_t u32;   // this is host order
	    struct {
		    uint8_t type;  // 126 for host type, 110 peer, 100 server
		    uint8_t local_hi; // ~0
		    uint8_t local_lo; // local priority in popularity
		    uint8_t component_id;  // (256-1) for rtp, (256-2) for rtcp
		};
    } priority;

    if( pair->sport == 0 ) return 0;

    priority.u32 = 0;
    priority.local_hi = ~0; // rfc5245 sec 4.1.2.1.
    priority.local_lo = ~0; // rfc5245 sec 4.1.2.1. only one address
    priority.type = 100;    // srflx type priority
    priority.component_id = 256 - 1;

    // rfc5245 sec 15.1. & draft-ietf-mmusic-ice-sip-sdp-39 sec 5.1.
    int k = snprintf(str, len,
                "a=candidate:2 1 UDP %u %s %u typ srflx raddr 0.0.0.0 rport 9\r\n",
                htonl(priority.u32), inet_ntoa(pair->sipv4), pair->sport);

    return k;  // not including trailing null
}

// rfc4566 - video payload type 96, audio 98
static int make_sdp_media(struct pair_t *pair, char *sdp, int len)
{
    int port = ice_session_port(pair->ice_session);
    char candidates[512];
    int clen = ice_get_candidates(pair->ice_session, candidates, sizeof(candidates));
    if( pair->sipv4.s_addr && pair->sport )
    {
        make_srflx_candidate(pair, candidates+clen, sizeof(candidates)-clen);
    }
    int n = snprintf(sdp, len,
                "a=setup:passive\r\n"  // actpass rfc5763 rfc4145
#ifdef DTLS_SRTP_OFF
                "m=application %u UDP/DTLS/SCTP webrtc-datachannel\r\n"
                "c=IN IP4 0.0.0.0\r\n"
                "%s"
                "a=sendrecv\r\n"
                "a=sctp-port:5000\r\n"
#else
                "a=group:BUNDLE video audio data\r\n"
                "m=video %u UDP/TLS/RTP/SAVPF 96\r\n"
                "c=IN IP4 0.0.0.0\r\n"
                "%s"
                "a=sendonly\r\n"
#ifdef DO_ICE_TRICKLE
#else
                "a=end-of-candidates\r\n"
#endif
                "a=mid:video\r\n"
                "a=rtcp-mux\r\n"
                "a=rtcp-mux-only\r\n"
                "a=rtpmap:96 H264/90000\r\n"
                "a=fmtp:96 profile-level-id=42e01f;packetization-mode=1\r\n"
                "m=audio 0 UDP/TLS/RTP/SAVPF 98\r\n"
                "c=IN IP4 0.0.0.0\r\n"
                "a=sendonly\r\n"
                "a=mid:audio\r\n"
                "a=bundle-only\r\n"
                "a=rtcp-mux\r\n"
                "a=rtcp-mux-only\r\n"
                "a=rtpmap:98 opus/48000/2\r\n"
//                "a=rtpmap:98 PCMU/8000\r\n"
                "m=application 0 UDP/DTLS/SCTP webrtc-datachannel\r\n"
                "c=IN IP4 0.0.0.0\r\n"
                "a=sendrecv\r\n"
                "a=mid:data\r\n"
                "a=bundle-only\r\n"
                "a=sctp-port:5000\r\n"
#endif // DTLS_SRTP_OFF
                "",
                port, candidates);

    return n;
}

static int make_sdp_offer(struct pair_t *pair, char *sdp, int len)
{
    int  n = 0;

    n += make_sdp_prefix(sdp + (n < len ? n : 0), (n < len ? len - n : 0));
    n += make_sdp_x509(pair, sdp + (n < len ? n : 0), (n < len ? len - n : 0));
    n += make_sdp_ice(pair, sdp + (n < len ? n : 0), (n < len ? len - n : 0));
    n += make_sdp_msid(sdp + (n < len ? n : 0), (n < len ? len - n : 0));
    n += make_sdp_media(pair, sdp + (n < len ? n : 0), (n < len ? len - n : 0));

    return n;  // excluding traill null
}

static void  sip_create_user(struct pair_t *pair)
{
    union {
        uint32_t  u32[2];
        uint64_t  u64;
    } a, b;

    a.u64 = randk();
    b.u64 = randk();
    // rfc5245 section 15.4. ufrag [4:256] chars, pwd [22:256] chars
    sprintf(pair->host_ice_ufrag, "%.8x", a.u32[0]);
    sprintf(pair->host_ice_pwd, "%.8x%.8x%.8x", a.u32[1], b.u32[0], b.u32[1]);

    LOGI("[%s:%u] new pair user=%s pwd=%s\n", __func__, __LINE__,
        pair->host_ice_ufrag, pair->host_ice_pwd);
}

//
// find a usable pair_t from sipx_t::pair[]
// assigned host_ice_user and host_ice_pwd
// notify iceagent to create a session endpoint
//
static void * sip_assign_pair(sipx_t *sipx)
{
    struct pair_t *pair=0;

    pthread_mutex_lock(&sipx->lock);

    int j;
    for(j = 0; j < SIP_MAX_USERS; j++)
    {
        if( sipx->pair[j].ice_session == 0 ) break;
    }

    if( j == SIP_MAX_USERS )
    {
        LOGI("[%s:%u] pair list overflow\n", __func__, __LINE__);
        goto exit;
    }

    pair = sipx->pair + j;

    memset(&(pair->peer), 0, sizeof(peer_t));

    pair->stun_id = 0;
    pair->sport = 0;
    pair->sipv4.s_addr = 0;

    pair->ice_session = ice_open_session(sipx->ice_ctx);

    if( pair->ice_session == 0 )
    {
        LOGI("[%s:%u] failed to open ice session\n", __func__, __LINE__);
        pair = 0;
        goto exit;
    }

    pair->last_heard = sip_utc_time();

    sip_create_user(pair);

exit:
    pthread_mutex_unlock(&sipx->lock);

    return pair;
}

////////////////////////////////////////////////////////////////////////////////
#define STUN_TIMEOUT 1000
#define WS_PORT  8802
#define WS_TIMEOUT 5000
enum
{
    E_OPCODE_TEXT=1,
    E_OPCODE_BINARY=2,
    E_OPCODE_CLOSE = 8,
    E_OPCODE_MAX=127
};
enum
{
    E_WS_HANDSHAKE=0,
    E_WS_UPGRADED,
    E_WS_PLAINTEXT,
    E_WS_CLOSE
};

// a pthread to produce an sdp offer
static void * sdp_offer_maker(struct pair_t *pair)
{
    struct sctx_t *sctx = pair->sctx;

    int sdp_len = 0;
    char *offer_sdp = 0;
    sdp_len = make_sdp_offer(pair, 0,0);

    offer_sdp = __builtin_alloca(sdp_len+1);
    make_sdp_offer(pair, offer_sdp, sdp_len+1);

    int rlen = ws_send_message(sctx, offer_sdp, sdp_len);
if(sdp_len>0)
    LOGI("[%s:%u]:%d %d\n%s", __func__, __LINE__, rlen, sdp_len, offer_sdp);
    (void)rlen;

    pair->sctx = 0;  // dis-associate

    if( sctx->fd )
    {
        if( sctx->state == E_WS_UPGRADED )
        {
            // websocket close
            ws_send_message(sctx, 0, 0);
        }
        sctx->state = E_WS_CLOSE;

        close(*(sctx->fd));
        *(sctx->fd) = -1;    // release socket context for "get sdp"
    }
    else
    {
        LOGI("[%s:%u] PANIC: null sctx->fd\n", __func__, __LINE__);
    }

    return 0;
}

#ifdef DO_ICE_TRICKLE
static void * sdp_trickle_ice(struct pair_t *pair)
{
    if( pair->sipv4.s_addr == 0 || pair->sport == 0)
    {
        LOGI("[%s:%u] null address", __func__, __LINE__);
        return 0;
    }
    struct sctx_t *sctx = pair->sctx;
    char candidate[128];
    int len = make_srflx_candidate(pair, candidate, sizeof(candidate));
    do{--len;} while(candidate[len]=='\r'||candidate[len]=='\n');
    candidate[len+1]='\0';
    char info[256];
    len = sprintf(info, "{\"candidate\":\"%s\",\"sdpMLineIndex\":0,\"usernameFragment\":\"%s\"}",
       candidate+2, pair->host_ice_ufrag);
    len = ws_send_message(sctx, info, len);
    LOGI("[%s:%u]: %d %s\n", __func__, __LINE__, len, info);

    pair->sctx = 0;  // dis-associate

    if( sctx->fd )
    {
        if( sctx->state == E_WS_UPGRADED )
        {
            // websocket close
            ws_send_message(sctx, 0, 0);
        }
        sctx->state = E_WS_CLOSE;

        close(*(sctx->fd));
        *(sctx->fd) = -1;    // release socket context for "get sdp"
    }
    else
    {
        LOGI("[%s:%u] PANIC: null sctx->fd\n", __func__, __LINE__);
    }

    return 0;
}
#endif // DO_ICE_TRICKLE

// called from ice_stun() - should never return positive
int  sip_addr_map(void *msg, int len, void *sess)
{
    // search for the pair that sent original binding request
    sipx_t *sipx = g_ctx + 0;
    struct pair_t *pair = 0;
    int j;
    for(j = 0, pair=sipx->pair; j < SIP_MAX_USERS; j++, pair++)
    {
        if( pair->ice_session == sess ) break;
    }

    if( j < SIP_MAX_USERS && pair->sctx )
    {
        // tell ice a good stun server
        ice_stun_rotate(pair->stun_id);
        get_stun_address(msg, len, &pair->sipv4.s_addr, &pair->sport);
#ifdef DO_ICE_TRICKLE
        sdp_trickle_ice(pair);
#else
        sdp_offer_maker(pair);
#endif
        LOGV("[%s:%u] server reflex %s:%u\n", __func__, __LINE__, inet_ntoa(pair->sipv4), pair->sport);
    }
    else
    {
        LOGV("[%s:%u] No matching pair found. j=%d\n", __func__, __LINE__, j);
    }

    return 0;
}

// expect two kind of command
// put sdp\r\n\r\n<sdp>
// get sdp\r\n\r\n
// dump <fmt> <utc> <duration>\r\n\r\n"
// ice candidate <host-user>:<remote-user> <candidate>\r\n\r\n"
static int sip_process_cmd(sctx_t *sctx, char *cmd, int len)
{
    const char *get_sdp="get sdp\r\n\r\n";
    const char *put_cmd="put sdp\r\n\r\n";
    const char *dumpwci="dump.wci?";
#ifdef DO_ICE_TRICKLE
    const char *ice_cmd="ice candidate ";
#endif
    int e = E_WS_CLOSE;
    int clen;

    if( clen = strlen(put_cmd), 0 == strncasecmp(put_cmd, cmd, clen) )
    {
        if( len > clen )
        {
            LOGI("[%s:%u]:\n%.*s", __func__, __LINE__, len, cmd);
            sip_process_sdp(sctx, cmd+clen, len - clen);
        }
        else
        {
            LOGI("[%s:%u] put sdp must be in one websocket send.\n",
                __func__, __LINE__);
        }
    }
    else if( clen = strlen(get_sdp), 0 == strncasecmp(get_sdp, cmd, clen) )
    {
        struct pair_t *pair = sip_assign_pair(sctx->sipx);
        if( pair != 0 )
        {
            pair->sctx = sctx;
#ifdef DO_ICE_TRICKLE
            sdp_offer_maker(pair);
#else
            pair->stun_id = ice_query_srflx(pair->ice_session, pair->stun_id);
            if( 0 > pair->stun_id )
            {
                // local candidates only
                sdp_offer_maker(pair);
            }
            else
            {
                // wait for srflx return to call sdp_offer_maker()
                e = sctx->state;
            }
#endif // DO_ICE_TRICKLE
        }
    }
    else if( clen = strlen(dumpwci), 0 == strncasecmp(dumpwci, cmd, clen) )
    {
        LOGI("[%s:%u]:\n%.*s", __func__, __LINE__, len, cmd);
        // socket /websocket to be closed see below
    }
#ifdef DO_ICE_TRICKLE
    else if( clen = strlen(ice_cmd), 0 == strncasecmp(ice_cmd, cmd, clen) )
    {
        LOGI("[%s:%u]:\n%.*s", __func__, __LINE__, len, cmd);
        sip_process_ice(sctx, cmd+clen, len - clen);
        // wait for srflx return to call sdp_offer_maker()
        e = sctx->state;
    }
#endif // DO_ICE_TRICKLE
    else
    {
        LOGI("[%s:%u] invalid command syntax.\n", __func__, __LINE__);
    }

    if( sctx->state != E_WS_CLOSE && e == E_WS_CLOSE )
    {
        // send 200 OK or websocket CLOSE
        ws_send_message(sctx, 0, 0);
        sctx->state = E_WS_CLOSE;
    }

    return e;
}

////////////////////////////////////////////////////////////////////////////////

static struct fv_t
{
    char *field;
    char *value;
} h_keys[] =
{
    {"Upgrade:", "websocket"},
    {"Connection:", "Upgrade"},
    {"Sec-WebSocket-Version", "13"}
};

//
// if @len <= 0, send close, otherwise send text
// @opcode = 1 for text, 2 for binary, 8 for close
static int ws_send_header(sctx_t *sctx, int opcode, int len)
{
    if( sctx->fd == 0 )
    {
        LOGI("[%s:%u] PANIC: null sctx->fd\n", __func__, __LINE__);
        return -1;
    }
    int fd = *(sctx->fd);
    if( fd == -1 )
    {
        LOGV("[%s:%u] WARNING: invalid socket\n", __func__, __LINE__);
        return -1;
    }

    uint8_t   header[10]={(0)};
    int       hlen=0;
    int       k=0;

    if( len <= 0 )
    {
        header[k++] = (1<<7) + 8; // FIN + close
        header[k++] = 0;  // payload length 0
        hlen = 2;
    }
    else
    {
        header[k++] = (1<<7) + opcode; // FIN + OP=text

        if( len < 126 )
        {
            header[k++] = len;
            hlen = 2;
        }
        else if( len < (1<<16) )
        {
            header[k++] = 126;
            header[k++] = len/256;
            header[k++] = len%256;
            hlen = 2 + 2;
        }
        else
        {
            header[k++] = 127;
            memset(header+k, 0, 8);
            // use low 4-byte of 8 bytes
            header[k+4] = ((len&0xff000000)>>24);
            header[k+5] = ((len&0x00ff0000)>>16);
            header[k+6] = ((len&0x0000ff00)>>8);
            header[k+7] = ((len&0x000000ff)>>0);
            hlen = 2 + 8;
        }
    }

    k = send(fd, header, hlen, MSG_NOSIGNAL);
    if( k != hlen ) return -2;

    return hlen;
}

// regular http response header
static int ws_http_header(sctx_t *sctx, int opcode, int len)
{
    if( sctx->fd == 0 )
    {
        LOGI("[%s:%u] PANIC: null sctx->fd\n", __func__, __LINE__);
        return -1;
    }
    int fd = *(sctx->fd);
    if( fd == -1 )
    {
        LOGV("[%s:%u] WARNING: invalid socket\n", __func__, __LINE__);
        return 0;
    }

    char header[256];

    int hlen = sprintf(header, "HTTP/1.1 200 OK\r\n");

    if( sctx->mime != 0 )
    {
        // contains content-type and optionally content-disposition
        // and line terminators
        hlen += sprintf(header+hlen, "%s", sctx->mime);
    }
    else if( opcode == E_OPCODE_TEXT )
    {
        hlen += sprintf(header+hlen, "Content-Type: text/plain\r\n");
    }
    else
    {
        // generic binary type
        hlen += sprintf(header+hlen, "Content-Type: application/octet-stream\r\n");
    }

    if( len > 0 )
    {
        hlen += sprintf(header + hlen, "Content-Length: %u\r\n", len);
    }

    hlen += sprintf(header + hlen, "\r\n");

    if( hlen != send(fd, header, hlen, MSG_NOSIGNAL) )
    {
        LOGV("[%s:%u] send(%d) errno=%d\n", __func__, __LINE__, hlen, errno);
        return -1;
    }

    return hlen;
}

__attribute__((unused))
static int ws_send_file(sctx_t *sctx, int op, int ff, int len)
{
    if( sctx->fd == 0 )
    {
        LOGI("[%s:%u] PANIC: null sctx->fd\n", __func__, __LINE__);
        return -__LINE__;
    }
    int fd = *(sctx->fd);
    if( sctx->state == E_WS_UPGRADED )
    {
        ws_send_header(sctx, op, len);
    }
    else if( sctx->state == E_WS_PLAINTEXT )
    {
        ws_http_header(sctx, op, len);
    }
    else
    {
        LOGI("[%s:%u] WARING wrong sctx->state\n", __func__, __LINE__);
        return -__LINE__;
    }

    //
    // linux specific -
    //
    int e = sendfile(fd, ff, 0, len);

    //LOGI("[%s:%u] sendfile(%d)=%d\n", __func__, __LINE__, len, e);

    // block until send queue is empty
    int q;
    do {
        usleep(10000); // 10ms
        e = ioctl(fd, TIOCOUTQ, &q);
    } while (e == 0 && q > 0);

    return e;
}

// @sctx is alloacted per client we don't need a mutex here to use the 
// session buffer assuming the client is legit (i.e. no extra incoming data
// after a "sdp get/put" command.)  - if client is malicious, server isn't
// hurt here
int ws_send_message(sctx_t *sctx, char *msg, int len)
{
    if( sctx->fd == 0 )
    {
        LOGI("[%s:%u] PANIC: null sctx->fd\n", __func__, __LINE__);
        return -1;
    }
    int fd = *(sctx->fd);
    if( fd == -1 )
    {
        LOGV("[%s:%u] WARNING: invalid socket\n", __func__, __LINE__);
        return 0;
    }

    int e = -1;

    switch(sctx->state)
    {
    case E_WS_UPGRADED:
        e = ws_send_header(sctx, E_OPCODE_TEXT, len);
        break;
    case E_WS_PLAINTEXT:
        e = len > 0 ? ws_http_header(sctx, E_OPCODE_TEXT, len) : 0;
        break;
    default:
        LOGV("[%s:%u] INVALID STATE %d\n", __func__, __LINE__, sctx->state);
        break;
    }
    // now send message body
    if( e >= 0 && msg != 0 && len >=0 )
    {
        e = send(fd, msg, len, MSG_NOSIGNAL);
    }

    return e;
}

// make sure @ctx->fd is valid
static int  ws_handshake(struct sctx_t *ctx)
{
    // sreach for crlfcrlf
    char *ptr = strstr(ctx->buf, "\r\n\r\n");
    if( ptr == 0 ) return E_WS_HANDSHAKE;

    int j;
    for(j = 0; j < sizeof(h_keys)/sizeof(h_keys[0]); j++)
    {
        ptr = strcasestr(ctx->buf, h_keys[j].field);
        if( ptr == 0 ) 
        {
            LOGV("[%s:%u] header %s not found\n",
                __func__, __LINE__, h_keys[j].field);
            return E_WS_PLAINTEXT;
        }
        ptr += strlen(h_keys[j].field);

        // skip whitespaces
        while(*ptr == ' ' || *ptr == '\t') ptr += 1;
        // search to \r\n
        int i, k=0;
        for(; ptr[k] && ptr[k] != '\r' && ptr[k] != '\n'; k++);
        int slen = strlen(h_keys[j].value);
        for(i=0; i + slen <= k; i++)
        {
            if( 0 == strncasecmp(ptr+i, h_keys[j].value, slen) ) break;
        }
        if( i + slen > k )
        {
            LOGV("[%s:%u] wrong field %s %s\n", 
                __func__, __LINE__, h_keys[j].field, h_keys[j].value);
            LOGV("[%s:%u] i=%d slen=%d k=%d\n", __func__, __LINE__, i, slen, k);
            return E_WS_PLAINTEXT;
        }
    }
    char *key = "Sec-WebSocket-Key:";
    ptr = strcasestr(ctx->buf, key);
    if( ptr == 0 )
    {
        LOGV("[%s:%u] missing field %s\n",  __func__, __LINE__, key);
        return -9;
    }
    ptr += strlen(key);
    // skip whitespaces
    while(*ptr == ' ' || *ptr == '\t') ptr += 1;
    // 
    for(j=0; isgraph(ptr[j]); j++);

    // per rfc6455 secion 1.3. concatenating guid below
    char *guid="258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    strcpy(ptr+j, guid);

    j += strlen(guid);

    uint8_t digest[SHA1HashSize]; //SHA1HashSize=20

    SHA1((uint8_t*)ptr, j, digest);

    strcpy(ctx->buf, 
           "HTTP/1.1 101 Switching Protocols\r\n"
           "Upgrade: websocket\r\n"
           "Connection: Upgrade\r\n" // safari doesn't like anything else
           "Sec-WebSocket-Accept: ");

    j = strlen(ctx->buf);

    j += Base64encode(ctx->buf+j, (const char*)digest, SHA1HashSize);
    j -= 1; // excluding trailling null
    strcpy(ctx->buf+j, "\r\n\r\n");

    j += 4;

    int e = send(*(ctx->fd), ctx->buf, j, 0);

    if( e != j ) return -8;  // disconnect

    ctx->len = 0;

    return E_WS_UPGRADED;
}

static char *sdp_method="POST /sipagent";

// plain http request - must be POST
static int ws_plaintext(struct sctx_t *sctx)
{
    int e = E_WS_CLOSE;

    if( strncasecmp(sdp_method, sctx->buf, strlen(sdp_method)) )
    {
        LOGV("[%s:%u] sdp requests must use POST method\n", __func__, __LINE__);
        return -2; //
    }
    // get context length
    const char *CLEN = "content-length:";
    char *bptr = strcasestr(sctx->buf, CLEN);
    if( bptr == 0 ) return -3;  // rfc2616 section 4.4

    int blen = strtol(bptr + strlen(CLEN), 0, 10);

    bptr = strstr(sctx->buf, "\r\n\r\n");

    if( bptr == 0 ) return -4; // should never occur

    bptr += 4;

    int hlen = (int)(bptr - sctx->buf);

    if( blen <= 0 || blen + hlen >= sctx->max )
    {
        LOGV("[%s:%u] bad content length %d\n", __func__, __LINE__, blen);
        return -3;
    }
    else if( sctx->len - hlen < blen )
    {
        return E_WS_PLAINTEXT; // need more
    }

    e = sip_process_cmd(sctx, bptr, blen);

    sctx->len = 0;

    return e;
}

static int ws_messaging(struct sctx_t *sctx)
{
    int len = sctx->len;

    if( len < 2 ) return E_WS_UPGRADED;

    uint8_t *m = (void*)sctx->buf;
    int   i;
    //int   fin = (m[0]&0x80);
    int   opcode = (m[0]&0x0f);

    uint8_t  mask_len = (m[1]&0x80)?4:0;
    unsigned int  payload_length = (m[1]&0x7f);

    if( payload_length <126 && len < 2 + payload_length + mask_len)
    {
        // need more
        return E_WS_UPGRADED;
    }
    if( payload_length == 126 && len < 4 + payload_length + mask_len)
    {
        // need more
        return E_WS_UPGRADED;
    }
    if( payload_length == 127 && len < 10 + payload_length + mask_len)
    {
        // need more
        return E_WS_UPGRADED;
    }
    uint8_t *msg = m + 2;

    if( payload_length == 126 ) 
    {
        payload_length = m[2]*256 + m[3];
        msg += 2;
    }
    else if( payload_length == 127 ) 
    {
        // rfc6455 sec 5.2. 8-byte as 64-bit number
        for(payload_length=0, i = 2; i < 10; i++)
        {
            payload_length = payload_length*256 + m[i];
        }
        msg += 8;
    }
    uint8_t *mask_ptr = 0;

    // rfc6445 5.1. client must mask; server must not mask
    if( mask_len > 0 )
    {
        mask_ptr = msg;
        msg += 4;
        for( i = 0; i < payload_length; i++)
        {
            msg[i] ^= mask_ptr[i%mask_len];
        }
    }

    int e = E_WS_CLOSE;

    switch( opcode )
    {
    case 0x01:
        e = sip_process_cmd(sctx, (char*)msg, payload_length);
        break;
    case 0x08:  // close
        if( mask_len > 0 )
        {
            // clear mask. ref. rfc6445 5.1.
            m[1] &= 0x7f;
            memmove(mask_ptr, msg, payload_length);
            sctx->len -= 4;
        }
        i = send(*(sctx->fd), m, sctx->len, 0);
        LOGV("[%s:%u] close sent %d\n", __func__, __LINE__, i);
        break;
    default:
        LOGI("[%s:%u] opcode %d, data ignored\n", __func__, __LINE__, opcode);
        break;
    }

    sctx->len = 0;

    return e;
}

static int  ws_handler(struct sctx_t *sctx)
{
    int e = -1;

    if( sctx->fd == 0 || *(sctx->fd) == -1 )
    {
        LOGI("[%s:%u] WARNING: null socket\n", __func__, __LINE__);
        return e;
    }

    if(sctx->len >= sctx->max ) return -1;

    sctx->buf[sctx->len] = '\0';  // terminate for strxxx() functions

    switch(sctx->state)
    {
    case E_WS_HANDSHAKE:
        e = ws_handshake(sctx);
        if( e != E_WS_PLAINTEXT ) break;
        sctx->state = e;
        // retain http headers and fall through
    case E_WS_PLAINTEXT:
        e = ws_plaintext(sctx);
        break;
    case E_WS_UPGRADED:
        e = ws_messaging(sctx);
        break;
    default:
        LOGI("[%s:%u] UNKOWN STATE!\n", __func__, __LINE__);
        e = -1;
        break;
    }

    return e;
}

static int  ws_get_tick(void)
{
    struct timespec  tv;
    clock_gettime(CLOCK_MONOTONIC, &tv);

    return (int)(tv.tv_sec*1000+tv.tv_nsec/1000000);
}

static void show_ws_state(int state, const char *func, int line)
{
    char *str;
    switch(state)
    {
    case E_WS_CLOSE: str = "E_WS_CLOSE"; break;
    case E_WS_HANDSHAKE: str = "E_WS_HANDSHAKE"; break;
    case E_WS_PLAINTEXT: str = "E_WS_PLAINTEXT"; break;
    case E_WS_UPGRADED: str = "E_WS_UPGRADED"; break;
    default: str = "UNKNOWN STATE"; break;
    }

    LOGV("[%s:%d] %s\n", func, line, str);
    (void)str;
}

// socket error/timeout - release pair_t object pending stun response
static void soc_release_pair(struct sctx_t *sctx)
{
    sipx_t *sipx = sctx->sipx;

    pthread_mutex_lock(&sipx->lock);

    struct pair_t *pair;
    int j;
    for(j = 0, pair=sipx->pair; j < SIP_MAX_USERS; j++, pair++)
    {
        if( pair->sctx == sctx )
        {
            pair->sctx  = 0;
            pair->ice_session = 0;
            LOGV("[%s:%u] sip socket closed\n", __func__, __LINE__);
        }
    }

    pthread_mutex_unlock(&sipx->lock);

    if( sctx->fd && *(sctx->fd) != -1)
    {
        close(*(sctx->fd));
        *(sctx->fd) = -1;
    }
}

static void * find_pair_by_sctx(struct sctx_t *sctx)
{
    sipx_t *sipx = sctx->sipx;

    struct pair_t *pair = 0;

    pthread_mutex_lock(&sipx->lock);
    int j;
    for(j = 0, pair=sipx->pair; j < SIP_MAX_USERS; j++, pair++)
    {
        if( pair->sctx == sctx ) break;
    }

    pthread_mutex_unlock(&sipx->lock);

    return pair;
}

// session timeout check - called every STUM_TIMEOUT
static int  session_checkup(struct sctx_t *sctx, int tick_count)
{
    // check if sip session timed out
    if( sctx->rtc + WS_TIMEOUT >= tick_count )
    {
        struct pair_t *pair = find_pair_by_sctx(sctx);

        if( pair && pair->stun_id > 0 )
        {
            pair->stun_id = ice_query_srflx(pair->ice_session, pair->stun_id);

            if( pair && pair->stun_id < 0 )
            {
                // make local candidate only offer
                sdp_offer_maker(pair);
            }
            return 0;  // next round
        }
    }
    // end sip session
    soc_release_pair(sctx);
    LOGV("[%s:%u] session %s:%u timed out\n", __func__, __LINE__,
            inet_ntoa(sctx->sa.sin_addr), ntohs(sctx->sa.sin_port));

    return -1;  // session ended

}

/*
static char *req=
"GET /chat HTTP/1.1\r\n"
"Host: server.example.com\r\n"
"Upgrade: websocket\r\n"
"Connection: Upgrade\r\n"
"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
"Origin: http://example.com\r\n"
"Sec-WebSocket-Protocol: chat, superchat\r\n"
"Sec-WebSocket-Version: 13\r\n"
"\r\n";
static char *resp=
"HTTP/1.1 101 Switching Protocols\r\n"
"Upgrade: websocket\r\n"
"Connection: Upgrade\r\n"
"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
"\r\n";
*/
void * sip_thread(void *icex)
{
    int  *quit = ice_quit_pointer(icex);

    sipx_t *sip_ctx = g_ctx + 0;

    sip_ctx->ice_ctx = icex;

    int soc[1];
    soc[0] = socket(AF_INET, SOCK_STREAM, 0);

    int j, e = 1;

    e = setsockopt(soc[0], SOL_SOCKET, SO_REUSEADDR, &e, sizeof(e));
    e = 1;
    e = setsockopt(soc[0], IPPROTO_TCP, TCP_NODELAY, &e, sizeof(e));

    struct sockaddr_in sa={(0)};
    sa.sin_family= AF_INET;
    sa.sin_addr.s_addr = 0;
    sa.sin_port=htons(WS_PORT);

    socklen_t slen = sizeof(sa);

    e = bind(soc[0], (struct sockaddr*)&sa, slen);

    e = listen(soc[0], 2);

    // max 1 udp and 2 tcp clients
    struct pollfd fds[3]={{-1, POLLIN, 0},
        {-1, POLLIN, 0}, {soc[0], POLLIN, 0}};

#define SIP_MAX_SOCKETS  (sizeof(fds)/sizeof(fds[0]))
#define SIP_MAX_CLIENTS  (SIP_MAX_SOCKETS-1)

    // max 2 tcp sessions
    struct sctx_t sctx[2]={(0)};
    for(j = 0; j < SIP_MAX_CLIENTS; j++)
    {
        sctx[j].fd = &fds[j].fd; // link to fds[j]
        sctx[j].sipx = sip_ctx;
        sctx[j].max = (1<<14);
        sctx[j].buf = malloc(sctx[0].max);
    }

    while( ! quit[0] )
    {
        e = poll(fds, sizeof(fds)/sizeof(fds[0]), STUN_TIMEOUT);

        if( e <= 0 ) goto prune;

        struct sctx_t *ctx;

        if( fds[SIP_MAX_CLIENTS].revents & POLLIN )
        {
            int fd = accept(fds[SIP_MAX_CLIENTS].fd,
                            (struct sockaddr*)&sa, &slen);

            LOGV("[%s:%u] accepted from %s:%u\n", __func__, __LINE__,
                inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));

            for(j=0; j < SIP_MAX_CLIENTS; j++)
            {
                ctx = sctx + j;

                if( fds[j].fd < 0 )
                {
                    fds[j].fd = fd;
                    ctx->len = 0;
                    ctx->sa = sa;
                    ctx->state = E_WS_HANDSHAKE;
                    ctx->rtc = ws_get_tick();
                    break;
                }
            }

            if( j == SIP_MAX_CLIENTS )
            {
                close(fd);
                LOGV(" rejected %s:%u\n",
                inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));
            }
        }

        for(j=0; j < SIP_MAX_CLIENTS; j++)
        {
            ctx = sctx + j;

            if( fds[j].fd >= 0 && fds[j].revents & POLLIN )
            {
                e = recv(fds[j].fd, ctx->buf + ctx->len, ctx->max - ctx->len, 0);
                if( e > 0 ) 
                {
                    ctx->len += e;

                    e = ws_handler(ctx);
                    if( e >= 0 && e != E_WS_CLOSE )
                    {
                        show_ws_state(e, __func__, __LINE__);
                        ctx->state = e;
                    }
                    else fds[j].revents |= POLLERR;
                }
                else
                {
                    // zero sized packet
                    fds[j].revents |= POLLERR;
                }
            }
            if( fds[j].fd >= 0 && fds[j].revents & POLLERR )
            {
                soc_release_pair(sctx+j); // [01/20/2023]

LOGV("[%s:%u] disconnect %s:%u\n", __func__, __LINE__,
    inet_ntoa(ctx->sa.sin_addr), ntohs(ctx->sa.sin_port));
            }
        }
        continue;  // bypass timeout checks
prune:
        // check for timeout sessions
        e = ws_get_tick();
        for(j=0; j < SIP_MAX_CLIENTS; j++)
        {
            if( fds[j].fd >= 0 )
            {
                session_checkup(sctx+j, e);
            }
        }
    }

    for(j = 0; j < SIP_MAX_SOCKETS; j++)
    {
        if( fds[j].fd >= 0 ) close(fds[j].fd);
        fds[j].fd = -1;
    }
    
    for(j = 0; j < SIP_MAX_CLIENTS; j++)
    {
        sctx->fd = 0;
        free(sctx[j].buf);
    }

    LOGV("[%s:%u] quit=%d\n", __func__, __LINE__, quit[0]);

    return 0;
}

