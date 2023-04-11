// file : iceagent.c
// date : 12/25/2019
//
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <poll.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <dirent.h>
#include <netdb.h>
#include <ctype.h>

#include "cryptlib/prng.h"
#include "x509cert.h"
#include "mediartp.h"
#include "sctpdtls.h"
#include "sctp4960.h"
#include "stun5389.h"

static char * ice_log_path = "/tmp/ice.log";

#define LOGV(...)
//#define LOGV printf
//#define LOGI(...)
#define LOGI printf

#define DATA_BUF_MAX   4096

#define ICE_USE_CTLMSG

#define ICE_SESSION_TIMEOUT 10

#define ICE_SESS_MAX  2

typedef struct icep_t
{
    void    *icex;  // top level icex_t*
    void    *dtls;  // dtls_ctx_t*
    void    *sctp;  // sctp_tcb_t*
    void    *crypto[2];  // session srtp crypto context rtp rtcp
    void    *rtpx;  // rtp media context rtpcx_t*
    int    (*call)(struct icep_t *);

    pthread_mutex_t lock[1];
    int      quit;  // quiting indicator

    int      use_candidate;
    int      port;
    int      sock;
    struct sockaddr_in from;
    uint8_t  mseg[DATA_BUF_MAX];
    int      mlen;
    int      last_checked; // time
#ifdef ICE_USE_CTLMSG
    struct in_pktinfo pin[1];
    struct iovec iov[2];  // up to 2 iovec
    uint8_t ctl[1024];
    struct msghdr mh[1];
#endif
}   icep_t;

typedef struct  icex_t
{
    int    *quit;

    void   *x509;  // certificate context

    icep_t  sess[ICE_SESS_MAX];
    
}   icex_t;

int * ice_quit_pointer(void *ctx)
{
    icex_t *icex = ctx;
    return (icex ? icex->quit : 0 );
}

void *ice_x509_context(void *ctx)
{
    icex_t *icex = ctx;
    return (icex ? icex->x509 : 0 );
}

void *session_x509_ctx(void *sess)
{
    return ice_x509_context(((icep_t*)sess)->icex);
}

void *get_srtp_cryptos(void *sess)
{
    return ((icep_t*)sess)->crypto;
}

void  set_srtp_cryptos(void *sess, void *tx_crypt, void *rx_crypt)
{
    ((icep_t*)sess)->crypto[0] = tx_crypt;
    ((icep_t*)sess)->crypto[1] = rx_crypt;
}

void ice_use_candidate(void *sess, int val)
{
    ((icep_t*)sess)->use_candidate = val;
}

#ifdef ICE_USE_CTLMSG
static int get_pkt_info(icep_t *sess, struct in_pktinfo *in)
{
    struct cmsghdr *cmsg=0;
    for (
        cmsg = CMSG_FIRSTHDR(sess->mh);
        cmsg != NULL;
        cmsg = CMSG_NXTHDR(sess->mh, cmsg))
    {
        if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO)
        {
            struct in_pktinfo *pi = (void*)CMSG_DATA(cmsg);
            // unsigned int ipi_ifindex;  Interface index
            // struct in_addr ipi_spec_dst; Local address
            // struct in_addr ipi_addr;  Header Destination address
            LOGV("[%s:%u] received ifindex %d dest %s\n", __func__, __LINE__,
                pi->ipi_ifindex, inet_ntoa(pi->ipi_spec_dst));
            if( in ) memcpy(in, pi, sizeof(struct in_pktinfo));
            return pi->ipi_ifindex;
        }
    }
    
    return -1; // invalid idindex
}
#endif

void ice_set_dtls_ctx(void *sess, void *ctx)
{
    ((icep_t*)sess)->dtls = ctx;
}

void * ice_get_dtls_ctx(void *sess)
{
    return ((icep_t*)sess)->dtls;
}

int  ice_session_port(void *sess)
{
    return ((icep_t*)sess)->port;
}

void * ice_session_peer(void *sess)
{
    return &(((icep_t*)sess)->from);
}

int ice_send_msg(icep_t *sess, struct sockaddr_in *to, uint8_t *msg, int len)
{
    int e = 0;
if( len > 1472) {LOGI("[%s:%u] packet size (%u) exceeds MTU\n", __func__, __LINE__, len);}
    pthread_mutex_lock(sess->lock);

    if( sess->sock == -1 ) { e = len; goto exit; }

#ifdef ICE_USE_CTLMSG
    char ctlbuf[CMSG_SPACE(sizeof(struct in_pktinfo))];
    struct iovec outvec[1] = {
        {.iov_base = msg, .iov_len = len}
    };
    struct msghdr msgh = {
        .msg_name = to,
        .msg_namelen = sizeof(*to),
        .msg_iov = outvec,
        .msg_iovlen = sizeof(outvec)/sizeof(struct iovec),
        .msg_control = ctlbuf,
        .msg_controllen = sizeof(ctlbuf),
        .msg_flags = 0
    };
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msgh);
    cmsg->cmsg_level = IPPROTO_IP;
    cmsg->cmsg_type = IP_PKTINFO;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
    memcpy(CMSG_DATA(cmsg), sess->pin, sizeof(struct in_pktinfo));
    e = sendmsg(sess->sock, &msgh, MSG_NOSIGNAL);
#else
    e = sendto(sess->sock, pkt, len, MSG_NOSIGNAL,
               (struct sockaddr*)to, sizeof(*to));
#endif
    if( e < 0 )
    {
        LOGI("[%s:%u] sent error errno=%d msg=%p len=%d\n",
            __func__, __LINE__, errno, msg, len);
        // [03/16/2021] if send() fails, just let session die
        close(sess->sock);
        sess->sock = -1;
    }

exit:
    pthread_mutex_unlock(sess->lock);

	return e;
}

int ice_send_pkt(icep_t *sess, uint8_t *pkt, int len)
{
    int e = 0;
if( len > 1472) {LOGV("[%s:%u] packet size (%u) exceeds MTU\n", __func__, __LINE__, len);}
    pthread_mutex_lock(sess->lock);

    if( sess->sock == -1 ) { e = len; goto exit; }

#ifdef ICE_USE_CTLMSG
    char ctlbuf[CMSG_SPACE(sizeof(struct in_pktinfo))];
    struct iovec outvec[1] = {
        {.iov_base = pkt, .iov_len = len}
    };
    struct msghdr msgh = {
        .msg_name = &(sess->from),
        .msg_namelen = sizeof(sess->from),
        .msg_iov = outvec,
        .msg_iovlen = sizeof(outvec)/sizeof(struct iovec),
        .msg_control = ctlbuf,
        .msg_controllen = sizeof(ctlbuf),
        .msg_flags = 0
    };
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msgh);
    cmsg->cmsg_level = IPPROTO_IP;
    cmsg->cmsg_type = IP_PKTINFO;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
    memcpy(CMSG_DATA(cmsg), sess->pin, sizeof(struct in_pktinfo));
    e = sendmsg(sess->sock, &msgh, MSG_NOSIGNAL);
#else
    e = sendto(sess->sock, pkt, len, MSG_NOSIGNAL,
               (struct sockaddr*)&sess->from, sizeof(sess->from));
#endif
    if( e < 0 )
    {
        LOGI("[%s:%u] sent error errno=%d pkt=%p len=%d\n",
            __func__, __LINE__, errno, pkt, len);
        // [03/16/2021] if send() fails, just let session die
        close(sess->sock);
        sess->sock = -1;
    }

exit:
    pthread_mutex_unlock(sess->lock);

	return e;
}
#define DTLS_RECORD_LEN  13
int ice_send_rec(icep_t *sess, uint8_t *rec, uint8_t *body, int blen)
{
    int e = 0;
// rfc6347 record layer header 13 bytes
if( blen > 1472-13) {LOGV("[%s:%u] packet size (%u) exceeds MTU\n", __func__, __LINE__, blen);}

    pthread_mutex_lock(sess->lock);

    if( sess->sock == -1 ) { e = blen; goto exit; }

#ifdef ICE_USE_CTLMSG
    char ctlbuf[CMSG_SPACE(sizeof(struct in_pktinfo))];
    struct iovec outvec[2] = {
        {.iov_base = rec, .iov_len = DTLS_RECORD_LEN},  // rfc6347 4.1
        {.iov_base = body, .iov_len = blen}
    };
    struct msghdr msgh = {
        .msg_name = &(sess->from),
        .msg_namelen = sizeof(sess->from),
        .msg_iov = outvec,
        .msg_iovlen = sizeof(outvec)/sizeof(struct iovec),
        .msg_control = ctlbuf,
        .msg_controllen = sizeof(ctlbuf),
        .msg_flags = 0
    };
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msgh);
    cmsg->cmsg_level = IPPROTO_IP;
    cmsg->cmsg_type = IP_PKTINFO;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
    memcpy(CMSG_DATA(cmsg), sess->pin, sizeof(struct in_pktinfo));
    e = sendmsg(sess->sock, &msgh, MSG_NOSIGNAL);
#else
    uint8_t *pkt=__builtin_alloca(DTLS_RECORD_LEN+blen);
    memcpy(pkt, rec, DTLS_RECORD_LEN);
    memcpy(pkt+DTLS_RECORD_LEN, body, blen);
    e = sendto(sess->sock, pkt, DTLS_RECORD_LEN+blen, MSG_NOSIGNAL,
               (struct sockaddr*)&sess->from, sizeof(sess->from));
#endif
    if( e < 0 )
    {
        LOGI("[%s:%u] error errno=%d\n", __func__, __LINE__, errno);
        close(sess->sock);
        sess->sock = -1;
    }

exit:
    pthread_mutex_unlock(sess->lock);

	return e;
}

// return utc seconds
static int32_t ice_get_time(void)
{
    struct timespec  tv;
    clock_gettime(CLOCK_MONOTONIC, &tv);

    return (int32_t)(tv.tv_sec);
}

// to be called from stun service
void  session_keepalive(void *sess)
{
    ((icep_t *)sess)->last_checked = ice_get_time();
}

//extern int stun_service(uint8_t *msg, int len, void *sess);
extern int sip_addr_map(uint8_t *msg, int len, void *sess);
static int  ice_stun(icep_t *sess)
{
    int e = 0;

    if( sess->mlen <= 0 ) return 0;

    // rfc5389 sec 6. STUN Message Structure
    if( (sess->mseg[0] & 0x01) )
    {
        // forward stun responses to sipagent
        e = sip_addr_map(sess->mseg, sess->mlen, sess);
    }
    else
    {
        e = stun_service(sess->mseg, sess->mlen, sess);
    }
    // check anything to send back
    if( e > 0 )
    {
        e = ice_send_pkt(sess, sess->mseg, e);
    }
    // reset buffer
    sess->mlen = 0;

    return e;
}

extern int dtls_service(uint8_t *msg, int len, void *sess);
static int  ice_dtls(icep_t *sess)
{
    int e = 0;

    dtls_service(sess->mseg, sess->mlen, sess);

    sess->mlen = 0;

    return e;
}
// to be upadted in parse_msdb_server()
static char g_media_path[128];
char * get_media_path() { return g_media_path; }

////////////////////////////////////////////////////////////////////////////////
static int  g_port_first;
static int  g_port_count;
static int  g_port_index;
static uint8_t *g_port_map;
static pthread_mutex_t g_port_lock = PTHREAD_MUTEX_INITIALIZER;

// overwrite if called multiple times
static void ice_map_ports(int start_port, int count)
{
    LOGV("[%s%u] start_port=%d count=%d\n", __func__, __LINE__,
        start_port, count);
    g_port_first = start_port;
    g_port_count = count;
    g_port_index = 0;
    if( count > 0 )
    {
        if( g_port_map ) __builtin_free(g_port_map);

        // to be freed in main()
        g_port_map = __builtin_malloc(1 + (count/8));
    }
    int k = 0;
    for(k = 0; k < count; k+=8)
    {
        g_port_map[k/8] = 0xff;
    }
}

static int  ice_take_port(void)
{
    pthread_mutex_lock(&g_port_lock);

    int idx=0;
    int k=0;
    for(k = 0; k < g_port_count; idx=k++)
    {
        idx = ((g_port_index + k) % g_port_count);
        int byt = (idx / 8);
        int bit = (idx % 8);
        if( g_port_map[byt] & (1<<bit) )
        {
            g_port_map[byt] ^= (1<<bit);
            break;
        }
    }

    if( g_port_count > 0 ) g_port_index = ((idx+1) % g_port_count);

    pthread_mutex_unlock(&g_port_lock);

    LOGV("[%s:%u] assign port=%d\n", __func__, __LINE__,
        (k < g_port_count ? g_port_first + idx : 0));

    return (k < g_port_count ? g_port_first + idx : 0);
}

static void ice_free_port(int port)
{
    LOGV("[%s:%u] free port=%d\n", __func__, __LINE__, port);

    if( port < g_port_first ||
        port >= g_port_first + g_port_count) return;

    pthread_mutex_lock(&g_port_lock);

    int byt = (port - g_port_first) / 8;
    int bit = (port - g_port_first) % 8;

    if( g_port_map[byt] & (1<<bit) )
    {
        LOGV("[%s:%u] PANIC: port=%d not previously taken\n",
            __func__, __LINE__, port);
    }

    g_port_map[byt] |= (1<<bit);

    pthread_mutex_unlock(&g_port_lock);
}

////////////////////////////////////////////////////////////////////////////////

extern void  sip_release_pair(void *sess);
extern void  dtls_cleanup_ctx(void *sess);

//
// this is called from ice_thread() and ice_rtp_quit() from rtp thread
//
void ice_halt_session(icep_t *sess)
{
    //pthread_mutex_lock(sess->lock);
    if( sess->quit != 0 ) //or __atomic_test_and_set(&sess->quit, __ATOMIC_SEQ_CST)
    {
        LOGV("[%s:%u] ice session already in quitting\n", __func__, __LINE__);
        return;
    }
    sess->quit = 1;

    LOGV("[%s:%u] ice session quit.\n", __func__, __LINE__);
    // close sock first to prevent re-entry
    if( sess->sock != -1 )
    {
        close(sess->sock);
        sess->sock = -1;
    }
    if( sess->port != 0 )
    {
        ice_free_port(sess->port);
        sess->port = 0;
    }

    // remove sdp pairing
    sip_release_pair(sess);

    // close media rtp sessions - do this before dtls_cleanup_ctx()
    if( sess->rtpx )
    {
        void *rtpx = sess->rtpx;
        sess->rtpx = 0; // to prevent from callback re-entry
        rtp_media_reset(rtpx);
    }

    // cleanup dtls context and srtp contexts
    if( sess->dtls )
    {
        dtls_cleanup_ctx(sess);
        sess->dtls = 0;
    }

    //pthread_mutex_unlock(sess->lock);
    sess->quit = 0; // clear quit indicator
}

// this is called in rtp thread in rtpmedia.c
static void ice_rtp_quit(void *sess)
{
    LOGV("[%s:%u] ice_rtp_quit\n", __func__, __LINE__);
    // free up endpoint context
    if( ((icep_t *)sess)->rtpx != 0 ) ice_halt_session(sess);
}

void  ice_source_srtp(void *sess)
{
    // start rtp media
    ((icep_t *)sess)->rtpx =
        rtp_media_setup(sess, (void*)ice_send_pkt, ice_rtp_quit);
}

void ice_set_sctp_tcb(void *sess, void *tcb)
{
    ((icep_t*)sess)->sctp = tcb;
}

int   ice_rtp_control(void *sess, void *cmd)
{
    int e = rtp_media_cntrl(((icep_t *)sess)->rtpx, cmd);
    return e;
}

static int  ice_srtp(icep_t *sess)
{
    int e = 0;

    rtp_media_inlet(sess->rtpx, sess->mseg, sess->mlen);

    sess->mlen = 0;

    return e;
}

static int  ice_base(icep_t *sess)
{
    uint8_t  b = sess->mseg[0];

    // demultiplexing as per rfc5764 section 5.1.2
    if( b < 2 )
    {
        return ice_stun(sess);
    }
    else if( 19 < b && b < 64 )
    {
        // ignore client hello until use_candidate
        // - but we are lite, so don't have to wait
        //if( sess->use_candidate )
        {
            return ice_dtls(sess);   // per rfc6347 dtls 1.2
        }
    }
    else if( 127 < b && b < 192 )
    {
        return ice_srtp(sess);
    }
    LOGV("[%s:%u] unknown packet type %x len=%d\n", __func__, __LINE__,
        b, sess->mlen);

    sess->mlen = 0;
    
    return 0;
}

// rfc5389 section 18.4
//#define STUN_PORT 3478
#define SRTP_PORT 64000

void * ice_thread(void *ctx)
{
    icex_t *icex = ctx;
    int    e, i; 

    struct pollfd fds[ICE_SESS_MAX];

    while( ! icex->quit[0] )
    {
        for( i = 0; i < ICE_SESS_MAX; i++)
        {
            fds[i].fd = icex->sess[i].sock;  // can be -1
            fds[i].events = POLLIN;
            fds[i].revents = 0;
        }

        e = poll(fds, sizeof(fds)/sizeof(fds[0]), 100);

        if( e > 0 ) for( i = 0; i < ICE_SESS_MAX; i++)
        {
            icep_t *sess = icex->sess + i;

            if( !(fds[i].revents & POLLIN) ) continue;

            pthread_mutex_lock(sess->lock);

            sess->mlen = 0; // clear message buffer
#ifdef ICE_USE_CTLMSG
            sess->mh->msg_flags = 0;
            e = recvmsg(sess->sock, sess->mh, 0);
            if( e > 0 ) get_pkt_info(sess, sess->pin);
#else 
            e = recvfrom(sess->sock, sess->mseg, DATA_BUF_MAX, 0,
                         (struct sockaddr*)&sess->from, &slen);
#endif  // ICE_USE_CTLMSG
//LOGV("[%s:%u] (%d) e=%d to port %u from %s:%u\n", __func__, __LINE__,
// i, e, sess->port, inet_ntoa(sess->from.sin_addr), ntohs(sess->from.sin_port));
            if( e >= 0 )
            {
                sess->mlen = e;
            }

            if( e > 0 && sess->call ) e = sess->call(sess);

            pthread_mutex_unlock(sess->lock);
        }

        // connectivity check
        int  now = ice_get_time();
        for( i = 0; i < ICE_SESS_MAX; i++)
        {
            icep_t *sess = icex->sess + i;
            if( (sess->port != 0) &&
                (now - sess->last_checked) > ICE_SESSION_TIMEOUT )
            {
                if( sess->dtls != 0 )
                    LOGI("[%s:%u] session %d connectivity timeout\n",
                        __func__, __LINE__, i);
                else
                    LOGI("[%s:%u] session %d handshake timeout\n",
                        __func__, __LINE__, i);

                ice_halt_session(sess);
            }
        }

    }
    LOGV("[%s:%u] quit=%d\n", __func__, __LINE__, icex->quit[0]);

    for( i = 0; i < ICE_SESS_MAX; i++)
    {
        icep_t *sess = icex->sess + i;

        if( sess->dtls != 0 ) ice_halt_session(sess);
    }
    
    return 0;
}

// defined in sipagent.c
extern void * sip_thread(void *ctx);


static void ice_setup_randk(void)
{
    uint8_t  seed[8];

    // reading from /dev/random can be slow at system startup
    // can be up to 3 miniutes on Pi-0 (4.4.50+)
    //int f = open("/dev/random", O_RDONLY);
    const char *pool = "/dev/urandom";
    int f = open(pool, O_RDONLY);
    if( f != -1 )
    {
        LOGV("reading %s - be patient..", pool);
        int j;
        for(j=0; j < 8; j++) if( read(f, seed+j, 1) ) {}
        LOGV(".done!\n");
    }
    else
    {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        *(uint32_t*)(seed+0) = (uint32_t)ts.tv_sec;
        *(uint32_t*)(seed+4) = (uint32_t)ts.tv_nsec;
    }    
    randk_seed_manual(*(unsigned long long*)seed);
//LOGV("[%s:%u] seed=%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x\n",
//__func__, __LINE__, seed[0], seed[1], seed[2], seed[3], 
//                    seed[4], seed[5], seed[6], seed[7]);
}

////////////////////////////////////////////////////////////////////////////////

#define EXCLUDE_LOOPBACK_IF
#define EXCLUDE_ALIAS_IF
//#define ONLY_ALIAS_IF
#define ICE_MAX_INTERFACES 16

static struct ip_intf_t {

    char if_name[IFNAMSIZ];
	char ip_addr[16];

}  g_ip_intf[ICE_MAX_INTERFACES];

static int  list_ip_intf(struct ip_intf_t *ipif, int max)
{
	int soc = socket(AF_INET, SOCK_DGRAM, 0);
	
	if( soc == -1 ) return 0;
	
	struct ifconf  ifc={(0)};
	
	int e = ioctl(soc, SIOCGIFCONF, &ifc);
	
    if( e == -1 )
    {
        printf(" SIOCGIFCONF error=%d\n", errno);
        return -1;
    }

    ifc.ifc_buf = __builtin_alloca(ifc.ifc_len);
    
    e = ioctl(soc, SIOCGIFCONF, &ifc);
    
    struct ifreq *ifr = ifc.ifc_req;
    
    int n;
    for(n=0; (char*)ifr < ifc.ifc_buf + ifc.ifc_len; ifr += 1)
    {
	    struct sockaddr_in *sa = (void*)&ifr->ifr_addr;
	    if( n < ICE_MAX_INTERFACES
#ifdef EXCLUDE_LOOPBACK_IF
          && strcmp(ifr->ifr_name, "lo")
#endif
#ifdef EXCLUDE_ALIAS_IF
          && 0 == strchr(ifr->ifr_name, ':')
#endif
#ifdef ONLY_ALIAS_IF
          && 0 != strchr(ifr->ifr_name, ':')
#endif
          )
	    {
			__builtin_strcpy(g_ip_intf[n].if_name, ifr->ifr_name);
			inet_ntop(AF_INET, &sa->sin_addr, g_ip_intf[n].ip_addr, 16);

LOGV("[%s:%u] [%u] %s %s\n", __func__, __LINE__,
	        n, g_ip_intf[n].if_name, g_ip_intf[n].ip_addr);

	        n += 1;
        }
    }

    return n;
}

////////////////////////////////////////////////////////////////////////////////

static int ice_start_service(icep_t *sess, int (*call)(struct icep_t *))
{
    struct sockaddr_in sa={(0)};
    socklen_t slen = sizeof(struct sockaddr_in);

    int e;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    e = 1;
    e = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &e, sizeof(e));

    e = (1<<18);
    e = setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &e, sizeof(e));
    if( e != 0 )
    {
        LOGV("[%s:%u] SO_RCVBUF failed errno=%d\n", __func__, __LINE__, errno);
    }
    e = (1<<20);
    e = setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &e, sizeof(e));
    if( e != 0 )
    {
        LOGV("[%s:%u] SO_SNDBUF failed errno=%d\n", __func__, __LINE__, errno);
    }
    sa.sin_family = AF_INET;
    sa.sin_port = htons(sess->port);

    e = bind(sock, (struct sockaddr*)&sa, slen);
    if( e != 0 )
    {
        LOGV("[%s:%u] bind failed %s:%u\n", __func__, __LINE__,
            inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));
        return -1;
    }

    e = getsockname(sock, (struct sockaddr*)&sa, &slen);
    if( e != 0 )
    {
        LOGV("[%s:%u] getsockname failed %s:%u\n", __func__, __LINE__,
            inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));
        return -2;
    }
    sess->port = ntohs(sa.sin_port);
LOGV("[%s:%u] getsockname %s:%u\n", __func__, __LINE__,
            inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));

#ifdef ICE_USE_CTLMSG
    e = 1;
    e = setsockopt(sock, IPPROTO_IP, IP_PKTINFO, &e, sizeof(e));
    sess->mh->msg_name = &(sess->from);
    sess->mh->msg_namelen = sizeof(sess->from);
    sess->iov[0].iov_base = sess->mseg;
    sess->iov[0].iov_len = DATA_BUF_MAX;
    sess->mh->msg_iov = (sess->iov);
    sess->mh->msg_iovlen = 1;
    sess->mh->msg_control = sess->ctl;
    sess->mh->msg_controllen = sizeof(sess->ctl);
#endif // ICE_USE_CTLMSG

    sess->call = call;

    sess->sock = sock;

    session_keepalive(sess);

    return 0;
}

// return session endpoint icep_t*
void * ice_open_session(void *icex)
{
    int i, e;

    for( i = 0; i < ICE_SESS_MAX; i++)
    {
        icep_t *sess = ((icex_t*)icex)->sess + i;

        // ref. ice_halt_session() sess->dtls must be 0 to re-use
        if( sess->sock != -1 || sess->dtls != 0 ) continue;

        sess->port = ice_take_port();

        e = ice_start_service(sess, ice_base);
LOGV("[%s:%u] add session port %d block[%d]\n", __func__, __LINE__, sess->port, i);
        if( e == 0 ) return sess; else break;
    }

    return 0;
}

// rfc5245 rfc8445
// debian would take the order of loopback, eth0 and its alias, wlan0
// this order is mapped to the priority in popularity see below
// the candidate priorities: (rfc5245 sec. 4.1.2.1. and 4.1.2.2)
// type priority: 126 for host type
// local priority: (ICE_MAX_INTERFACES - j) or j
//                 where j is the index in g_ip_intf
// component ID: 1 for rtp, 2 for rtcp
int  ice_get_candidates(void *sess, char *str, int len)
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

    if( sess == 0 ) return 0;
    int port = ((icep_t*)sess)->port;

    priority.u32 = 0;
    priority.local_hi = ~0; // rfc5245 sec 4.1.2.1.
    priority.type = 126; // host type priority
    priority.component_id = 256 - 1;
    char  candi[128];
    int j, k=0, w;
    for(j =ICE_MAX_INTERFACES-1; j >=0; j--)
    {
		if( g_ip_intf[j].if_name[0] )
		{
			priority.local_lo = j;
			// rfc5245 sec 15.1.
			w = sprintf(candi,
                "a=candidate:1 1 UDP %u %s %u typ host\r\n",
			    htonl(priority.u32), g_ip_intf[j].ip_addr, port);
			if( str && k + w < len )
			{
				strcpy(str + k, candi);
			}
			k += w;
		}
	}

    return k;  // not including trailing null
}

int  webrtc_send_utc(void *ice_sess, uint64_t utc)
{
    int e = 0;
    if( ice_sess == 0 ) {
        LOGV("[%s:%u] null ive session\n", __func__, __LINE__);
        return e;
    }
    void *dtls_ctx = ice_get_dtls_ctx(ice_sess);

    if( dtls_ctx == 0 ) {
        LOGV("[%s:%u] null dtls_ctx\n", __func__, __LINE__);
        return e;
    }

    void *sctp_tcb = dtls_get_sctp(dtls_ctx);

    if( sctp_tcb == 0 )
    {
        // this is fine at startup
        //LOGV("[%s:%u] null sctp_tcb\n", __func__, __LINE__);
        return e;
    }

    char  str[32]; // 8-byte integer max 20 bytes: 18446744073709551615
    int len = sprintf(str, "videotime:%llu", (long long unsigned int)utc);

    e = sctp_to_webrtc(sctp_tcb, str, len);

    return e;
}

////////////////////////////////////////////////////////////////////////////////
// stun server list -
// the number of allowed stun queries is limited by these 3 timeout values
// (1) STUN_TIMEOUT - 1000 ms - defined in sipagent.c
// (2) WS_TIMEOUT - 5000 ms - defined in sipagent.c
// (3) ICE_SESSION_TIMEOUT - 10 seconds - defined in iceagent.c
// given the values about, there should not be more than 5 stun servers
// the sip session would have expired by the time the 6th stun query is made
//
#define MAX_STUN_SERVERS  5
static char *g_stun_server[MAX_STUN_SERVERS]=
{
    0, 0, 0, 0, 0
};

// rotate server list so that entry of index becomes first entry
// note that @index_next is the one returned by previous call to
// ice_stun_server()
void ice_stun_rotate(int index_next)
{
    int index = index_next - 1;

    if( index <= 0 || index >= MAX_STUN_SERVERS) return;

    char *one = g_stun_server[0];
    g_stun_server[0] = g_stun_server[index];
    g_stun_server[index] = one;

    return;
}

//
// @addr points to a struct sockaddr_in struct
//
int  ice_stun_server(int index, void *addr)
{
    if( index < 0 || index >= MAX_STUN_SERVERS || g_stun_server[index] == 0)
    {
        index = 0;
    }
    if( g_stun_server[index] == 0 ) return -1;

    int n = strlen(g_stun_server[index]);

    if( n == 0 ) return -1;

    char *name = __builtin_alloca(n+1);

    strcpy(name, g_stun_server[index]);
LOGV("[%s:%u] stun server: %s\n", __func__, __LINE__, name);
    char *end = strchr(name, ':');

    int port = STUN_PORT;

    if( end )
    {
        *end = '\0';
        port = strtol(end+1, 0, 10);
    }

    struct hostent * hent = gethostbyname(name);

    if( hent == 0 || hent->h_length < 1 )
    {
        LOGV("[%s:%u] unable to resolve name %s\n", __func__, __LINE__, name);
        // try next entry
        return ice_stun_server(index+1, addr);
    }
    struct sockaddr_in *sa = addr;

    sa->sin_addr = *(struct in_addr*)hent->h_addr_list[0];
    sa->sin_port = htons(port);
    sa->sin_family = AF_INET;

    return index+1;  // next index
}

//
// return nonpositive if there is no stun server available
// return next stun server index otherwise (for retries)
//
int  ice_query_srflx(void *sess, int index)
{
    struct sockaddr_in sa={(0)};

    int e = ice_stun_server(index, &sa);

    if( e < 0 ) return e;

    uint8_t *msg = __builtin_alloca(STUN_MSG_MAX);

    int len = create_stun_message(msg, STUN_MSG_MAX, e_stun_class_request, 0);

    len = ice_send_msg(sess, &sa, msg, len);

    return len > 0 ? e : -1;
}

////////////////////////////////////////////////////////////////////////////////

static int g_quit;
static void sig_int(int sig)
{
    g_quit = 1;
}

// @range="<start-port>:<end-port>
static void parse_ports_range(char *range)
{
    char *colon = strchr(range, ':');
    if( colon == 0 ) colon = strchr(range, '-');
    int start_port = strtol(range, 0, 10);
    int end_port = 0;
    if( colon ) end_port = strtol(colon+1, 0, 10);

    if( start_port > 0 && start_port <= end_port && end_port < 65535 )
    {
        // overwrite if called multiple times
        ice_map_ports(start_port, end_port - start_port + 1);
    }
}

#ifdef VIDEO_VIA_FILE
static void parse_media_path(char *path)
{
    if( strlen(path) < sizeof(g_media_path) )
    {
        strcpy(g_media_path, path);
    }
}
#endif

static void parse_stun_server(char *server)
{
    int k = 0;
    char *ptr = server;
    for(k = 0; ptr[0] && k < MAX_STUN_SERVERS; k++)
    {
        if( g_stun_server[k] != 0 ) continue;

        ptr = strchr(server, ',');

        if( ptr == 0 )
        {
            // move @ptr to end of line - replace \r\n with \0
            for( ptr = server; ptr[0]; ptr++ )
            {
                if( ! isgraph(ptr[0]) )
                {
                    ptr[0] = '\0';
                    break;
                }
            }
        }

        int len = (int)(ptr - server);

        g_stun_server[k] = __builtin_malloc(len + 1);
        strncpy(g_stun_server[k], server, len);
        g_stun_server[k][len] = '\0';

        server = ptr + 1;
    }
}

static void parse_config_file(const char *conf)
{
    FILE *fp = fopen(conf, "rb");

    if( fp == 0 )
    {
        LOGV("[%s:%u] failed to open %s\n", __func__, __LINE__, conf);
        return;
    }

    char  line[256];
    int   pos=-1;
    fseek(fp, SEEK_SET, 0);
    char *key = "[webrtc ports]";
    while( fgets(line, sizeof(line), fp) )
    {
        // skip lines starting with white spaces or #
        if( line[0] == '#') continue;

        if( pos < 0 && 0 != strncmp(line, key, strlen(key)) ) continue;
        if( pos < 0)
        {
            pos = 0;
            continue;
        }

        if( !isgraph(line[0]) ) break;

        parse_ports_range(line);
    }

    pos=-1;
    fseek(fp, SEEK_SET, 0);
    key = "[stun servers]";
    while( fgets(line, sizeof(line), fp) )
    {
        // skip lines starting with white spaces or #
        if( line[0] == '#') continue;

        if( pos < 0 && 0 != strncmp(line, key, strlen(key)) ) continue;
        if( pos < 0)
        {
            pos = 0;
            continue;
        }

        if( !isgraph(line[0]) ) break;

        parse_stun_server(line);
    }

    fclose(fp);
}

static void show_init_config(void)
{
    if( g_port_count > 0 )
    {
        LOGI("Ports range %d:%d total %d ports available\n",
            g_port_first, g_port_first+g_port_count-1, g_port_count);
    }
    else LOGI("No ice ports map defined\n");
    int k, n=0;
    for(k = 0; k < MAX_STUN_SERVERS; k++)
    {
        if( g_stun_server[k] == 0 ) break;
        n += 1;
        LOGI("stun server[%d]: %s\n", k, g_stun_server[k]);
    }
    LOGI("%d stun servers defined\n", n);
}

static int redirect_log(char *log_pipe)
{
    // check if no tty is attached
    int tty = open("/dev/tty", O_RDONLY);
    if( tty != -1 )
    {
        close(tty);
        return 0;  // log to tty
    }

    // create log pipe
    umask(0111);
    if( -1 == mkfifo(log_pipe, 0666) && errno != EEXIST )
    {
        printf("Failed mkfifo %s err=%d\n", log_pipe, errno);
        return -1;
    }

    //  for linux open with O_RDWR to avoid being blocked
    int fifo = open(log_pipe, O_RDWR|O_NONBLOCK|O_CLOEXEC);

    if( fifo != -1 )
    {
        // redirect stdout to log pipe
        dup2(fifo, STDOUT_FILENO);
        close(fifo);
    }

    // disable stdout block buffering for fifo redirect
    //setbuf(stdout, 0);
    setlinebuf(stdout);

    return 1;
}

static void sig_user1(int sig){(void)sig;}

int main(int argc, char *argv[])
{
    struct sigaction action;
    action.sa_handler = sig_int;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    sigaction(SIGINT, &action, NULL);

    // SIGUSR1 is used to wake up blocking read()
    action.sa_handler = sig_user1;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    sigaction(SIGUSR1, &action, NULL);

    int k;
    for( k = 1; k < argc; k++ )
    {
        if( 0 == strncmp(argv[k], "-h", 2 ) )
        {
#ifdef VIDEO_VIA_FILE
            printf("Usage: %s path=<media-path>"
                   " stuns=<stun-server>:<port> cfg=<config-file>\n",
                   argv[0]);
#endif
            return 0;
        }
#ifdef VIDEO_VIA_FILE
        else if( 0 == strncmp(argv[k], "path=", 5) )
        {
            parse_media_path(argv[k] + 5);
        }
#endif
        else if( 0 == strncmp(argv[k], "ports=", 6) )
        {
            parse_ports_range(argv[k] + 6);
        }
        else if( 0 == strncmp(argv[k], "stuns=", 6) )
        {
            parse_stun_server(argv[k] + 6);
        }
        else if( 0 == strncmp(argv[k], "cfg=", 4) )
        {
            parse_config_file(argv[k] + 4);
        }
        else
        {
            printf("unknown command option: %s\n", argv[k]);
        }
    }
    if( argc == 1 ) // if no options are specified, try platform.ini
    {
        const char *cfg="etc/platform.ini";
        FILE *f=fopen(cfg, "r");
        if( f )
        {
            fclose(f);
            parse_config_file(cfg);
        }
    }
#ifdef VIDEO_VIA_FILE
    if( g_media_path[0] == 0 )
    {
        printf(" Missing media file path. run with -h for help.\n");
        return 0;
    }
#endif
    // if there is not tty attached, redirect stdout to @ice_log_path
    redirect_log(ice_log_path);

    show_init_config();

    ice_setup_randk();

    // [12/09/2020] interface may not be up at startup
    while( 0 == list_ip_intf(g_ip_intf, ICE_MAX_INTERFACES) )
    {
        sleep(1);
    }

    int i, e;

    icex_t *icex = __builtin_malloc(sizeof(icex_t));

    memset(icex, 0, sizeof(icex_t));

    icex->quit = &g_quit;

    for( i = 0; i < ICE_SESS_MAX; i++)
    {
        icex->sess[i].icex = icex;  // top level context
        icex->sess[i].sock = -1;
        pthread_mutexattr_t attr[0];
        pthread_mutexattr_init(attr);
        pthread_mutexattr_settype(attr, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(icex->sess[i].lock, attr);
        pthread_mutexattr_destroy(attr);
    }

    char cert_path[]="etc/cert.pem";
    // if there is no subdirectory etc, put it in working directory
    {
        DIR *etc = opendir("etc");
        if( etc ) closedir(etc); else strcpy(cert_path, "cert.pem");

        // check certificate expiration
        struct stat st;
        if( 0 == stat(cert_path, &st) )
        {
            // x509cert.c created certificate with validity of 365 days
            if( st.st_mtime > 365*24*3600 )
            {
                unlink(cert_path);
                LOGI("{%s} certificate %s has expired. re-create\n", argv[0], cert_path);
            }
        }
    }
    icex->x509 = init_x509_context(cert_path);

    if( 0 == icex->x509 )
    {
		LOGV("{%s} unable to initialize x509 context\n", argv[0]);
		goto exit;
	}

    pthread_t sip_task;
    
    e = pthread_create(&sip_task, 0, sip_thread, icex);

    if( e != 0 ) goto exit;

    sctp_init(); // dtls lacks initialization routine, so put it here

    pthread_t ice_task;

    // create a ice agent thread
    e = pthread_create(&ice_task, 0, ice_thread, icex);

    if(e == 0) pthread_join(ice_task, 0);

    if( g_quit == 0 ) g_quit = -2;

    pthread_join(sip_task, 0);

    sctp_exit();

exit:
    LOGV("{%s} done.\n", argv[0]);

    if( g_port_map ) __builtin_free(g_port_map);

    for(e = 0; e < MAX_STUN_SERVERS; e++ )
    {
        if( g_stun_server[e] )
        {
LOGV("[%s:%u] freeing %s\n", __func__, __LINE__, g_stun_server[e]);
            __builtin_free(g_stun_server[e]);
            g_stun_server[e] = 0;
        }
    }

    for( i = 0; i < ICE_SESS_MAX; i++)
    {
        pthread_mutex_destroy(icex->sess[i].lock);
    }

    if( icex->x509 ) free_x509_context(icex->x509);

    __builtin_free(icex);

    return 0;
}

