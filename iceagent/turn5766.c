// file : truen5766.c
// date : 02/10/2023
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

#include "cryptlib/crc.h"
#include "cryptlib/md5.h"
#include "cryptlib/hmac.h"
#include "turn5766.h"

//#define LOGV(...)
//#define LOGI(...)
#define LOGV printf
#define LOGI printf

#define STUN_USERNAME_MAX   128
#define STUN_PASSWORD_MAX   32

#define DATA_BUF_MAX   4096

#define TURN_PERMISSION_TTL (5*60) // rfc5766 sec 2.3.
#define TURN_CHANNEL_TTL   (10*60) // rfc5766 sec 2.5.
#define TURN_RELAY_TTL     (10*60) // rfc5766 sec 5.

// rfc5389 section 18.4.   rfc8656 4.1.
#define STUN_PORT 3478

#define TURN_CLIENTS_MAX 4

#define SOCKET_POLL_INTERVAL (10)  // milliseconds

enum USER_STATE
{
    state_null,
    state_athenticated,
    state_allocated,
};

typedef struct userx_t // client
{
    struct sockaddr_in client;   // client host

    struct sockaddr_in relayed;  // relayed transport
    uint32_t   mapped_peer[1];   // peer ip address network-order
    uint32_t   mapped_port[1];   // peer port for channel network-order

    char   username[STUN_USERNAME_MAX];
    char   password[STUN_PASSWORD_MAX];

    enum USER_STATE user_state;
    int      allocated;
    int      permission_refreshed;
    int      allocation_refreshed; // utc in seconds
    int      channel_number;
    int      channel_refreshed;

}  userx_t;

typedef struct endpx_t
{
    int      socket;
    int      mlen;
    uint8_t  head[4];
    uint8_t  mseg[DATA_BUF_MAX]; // inbound
    uint8_t  mout[DATA_BUF_MAX]; // outbound
    
    struct in_pktinfo pin[1];
    struct iovec iov[2];  // up to 2 iovec
    uint8_t ctl[1024];
    struct msghdr mh[1];

    struct sockaddr_in from;
 
}  endpx_t;

typedef struct turnx_t
{
    // client context
    userx_t  userx[TURN_CLIENTS_MAX];

    // relayed transport endpoints  + server endpoint
    endpx_t  endpx[TURN_CLIENTS_MAX+1];

    int turn_port; // server port number
    
    int *quit;

}  turnx_t;

////////////////////////////////////////////////////////////////////////
__attribute__((unused))
static void dump_hex(void *hex, int len)
{
    int j;
    for(j = 0;  j < len; j++)
    {
        if( j>0 && (j%16==0) ) printf("\n");
        printf("%.2x ", ((uint8_t*)hex)[j]);
    }
    printf("\n");
}

static char USERNAME[128]="123";
static char PASSWORD[128]="345";
static char *NONCE="abcdefgh";
static char *REALM="ettaceo";
static struct in_addr PEER_IF_ADDR={(0)};

static int setup_credential(const char *user, const char *pass)
{
    size_t ulen;
    size_t plen;
    if( user == 0 || pass == 0 || (ulen = strlen(user)) ==0 ||
        (plen = strlen(pass)) == 0 )
    {
        return -1;
    }
    if( ulen >= sizeof(USERNAME) )
    {
        ulen = sizeof(USERNAME) - 1;
    }
    if( plen >= sizeof(PASSWORD) )
    {
        plen = sizeof(PASSWORD) - 1;
    }
    strcpy(USERNAME, user);
    strcpy(PASSWORD, pass);
/*
    size_t n = strlen(arg);
    if( n >= sizeof(USERNAME) + sizeof(PASSWORD) )
    {
        return - __LINE__;
    }
    char *ptr = strchr(arg, ':');
    if( ptr == 0 )
    {
        return - __LINE__;
    }
    if( (size_t)(ptr - arg) >= sizeof(USERNAME) )
    {
        return - __LINE__;
    }
    __builtin_memset(USERNAME, 0, sizeof(USERNAME));
    __builtin_memcpy(USERNAME, arg, (size_t)(ptr - arg));

    ptr += 1;
    n -= (size_t)(ptr - arg);
    if( n > sizeof(PASSWORD) )
    {
        return - __LINE__;
    }
    __builtin_memset(PASSWORD, 0, sizeof(PASSWORD));
    __builtin_memcpy(PASSWORD, ptr, n);
*/
    LOGV("[%s:%u] USERNAME=\"%s\", PASSWORD=\"%s\"\n", __func__, __LINE__,
        USERNAME, PASSWORD);
    return 0;
}

static int set_peer_net_if(const char *peerif)
{
	int soc = socket(AF_INET, SOCK_DGRAM, 0);
	if( soc == -1 ) return 0;
	struct ifconf  ifc={(0)};
	int e = ioctl(soc, SIOCGIFCONF, &ifc);
    if( e == -1 )
    {
        LOGI("[%s:%u] SIOCGIFCONF error=%d\n", __func__, __LINE__, errno);
        return -1;
    }
    ifc.ifc_buf = __builtin_alloca(ifc.ifc_len);
    e = ioctl(soc, SIOCGIFCONF, &ifc);
    struct ifreq *ifr = ifc.ifc_req;
    for(; (char*)ifr < ifc.ifc_buf + ifc.ifc_len; ifr += 1)
    {
	    if( strcmp(ifr->ifr_name, "lo") && (! strcmp(ifr->ifr_name, peerif)) )
        {
            struct sockaddr_in *sa = (void*)&ifr->ifr_addr;
            PEER_IF_ADDR = sa->sin_addr;
            break;
        }
    }
    
    LOGV("[%s:%u] PEER_IF_ADDR=%s\n", __func__, __LINE__, inet_ntoa(PEER_IF_ADDR));
    return PEER_IF_ADDR.s_addr ? 0 : -1;
}

// return utc seconds
static int32_t turn_get_time(void)
{
    struct timespec  tv;
    clock_gettime(CLOCK_MONOTONIC, &tv);

    return (int32_t)(tv.tv_sec);
}

static void turn_halt_client(turnx_t *turnx, int index)
{
    userx_t *userx = turnx->userx + index;
    endpx_t *endpx = turnx->endpx + index;

    if( endpx->socket != -1 )
    {
        close(endpx->socket);
        endpx->socket = -1;
    }

    userx->channel_number = 0;
    userx->mapped_peer[0] = 0;
    userx->mapped_port[0] = 0;
    userx->allocated = 0;
}

static int get_pkt_info(endpx_t *endpx, struct in_pktinfo *in)
{
    struct cmsghdr *cmsg=0;
    for (
        cmsg = CMSG_FIRSTHDR(endpx->mh);
        cmsg != NULL;
        cmsg = CMSG_NXTHDR(endpx->mh, cmsg))
    {
        if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO)
        {
            struct in_pktinfo *pi = (void*)CMSG_DATA(cmsg);
            // unsigned int ipi_ifindex;  Interface index
            // struct in_addr ipi_spec_dst; Local address
            // struct in_addr ipi_addr;  Header Destination address
//LOGV("[%s:%u] received ifindex %d dest %s\n", __func__, __LINE__,
//    pi->ipi_ifindex, inet_ntoa(pi->ipi_spec_dst));
            if( in ) memcpy(in, pi, sizeof(struct in_pktinfo));
            return pi->ipi_ifindex;
        }
    }

    return -1; // invalid idindex
}

static int turn_class_is_valid(uint16_t msg_class)
{
    return (msg_class <= e_stun_class_error); 
}

static int turn_method_is_valid(uint16_t method)
{
    return (method == e_stun_method_binding) ||
           ((method >=e_turn_method_allocate) &&
            (method < e_turn_method_max) &&
            (method != 0x0005)); 
}

// @value_len can be zero; in that case @value is ignored
int  turn_append_attribute(uint8_t *msg, int size,
                           int attr_type, int value_len, void *value_ptr)
{
    if( size < sizeof(stun_hdr_t) ) return -1;

    // rfc5389 section 15:
    // Each STUN attribute MUST end on a 32-bit boundary
    int length = (value_len+3)/4*4;

    stun_hdr_t *hdr = (void*)msg;
    int msg_len = sizeof(stun_hdr_t) + ntohs(hdr->length);

    stun_tlv_t *tlv = (void*)(msg + msg_len);

    msg_len += sizeof(stun_tlv_t) + length;

    if( msg_len > size ) return -2;  // buffer overflow

    memset(tlv, 0, sizeof(stun_tlv_t) + length);
    tlv->type = htons(attr_type);
    tlv->length = htons(value_len);
    if( length > 0 ) memcpy(tlv->value, value_ptr, length);

    hdr->length = htons(msg_len - sizeof(stun_hdr_t));

    return msg_len;
}

static int  turn_binding_request(endpx_t *client)
{
    int len;
    struct sockaddr_in *sa = &(client->from);

    LOGV("[%s:%u] MAPPED_ADDRESS %s:%u\n", __func__, __LINE__,
        inet_ntoa(sa->sin_addr), ntohs(sa->sin_port));

    stun_map_t map={(0)};
    map.family = e_IPv4;
    map.port = sa->sin_port;
    *((struct in_addr*)(map.address)) = sa->sin_addr;
    map.port ^= htons(0x2112);
    *((uint32_t*)(map.address)) ^= htonl(0x2112A442);
    len = append_stun_attribute(client->mout, STUN_MSG_MAX, 
                                e_XOR_MAPPED_ADDRESS, 8, &map);
    (void)len;
    return 0;
}

static stun_tlv_t * turn_fetch_attribute(void *msg, int len, int attribute,
                                         stun_tlv_t *tlv)
{
    while( (tlv = get_next_attribute(msg, len, tlv)) )
    {
        if( attribute == ntohs(tlv->type) )
        {
            return tlv;
        }
    }
    return 0;
}

static void turn_unauthorize(endpx_t *client, char *nonce, char *realm)
{
    // add nouce in response - rfc2617 3.2.1. rfc5389 10.2.2.
    turn_append_attribute(client->mout, STUN_MSG_MAX,
                            e_NONCE, strlen(nonce), nonce);
    // add realm in response - rfc5389 10.2.2.
    turn_append_attribute(client->mout, STUN_MSG_MAX,
                            e_REALM, strlen(realm), realm);
}

static int turn_check_integrity(turnx_t *turnx, endpx_t *client)
{
    // check allocation requisite
    stun_tlv_t *msg_integrity = turn_fetch_attribute(client->mseg,
                                    client->mlen, e_MESSAGE_INTEGRITY, 0);
    if( msg_integrity == 0 || ntohs(msg_integrity->length) != 20 ) // sha1
    {
        turn_unauthorize(client, NONCE, REALM);
        return 401;
    }
    stun_tlv_t *msg_user = turn_fetch_attribute(client->mseg,
                                    client->mlen, e_USERNAME, 0);
    if( msg_user == 0)
    {
        return 400; // bad request rfc5389 10.2.2.
    }
    stun_tlv_t *msg_realm = turn_fetch_attribute(client->mseg,
                                    client->mlen, e_REALM, 0);
    if( msg_realm == 0)
    {
        return 400; // bad request rfc5389 10.2.2.
    }
    stun_tlv_t *msg_nonce = turn_fetch_attribute(client->mseg,
                                    client->mlen, e_NONCE, 0);
    if( msg_nonce == 0)
    {
        return 400; // bad request rfc5389 10.2.2.
    }
    size_t nonce_len = ntohs(msg_nonce->length);
    if( nonce_len != strlen(NONCE) ||
        0 != memcmp(msg_nonce->value, NONCE, nonce_len) )
    {
        turn_unauthorize(client, NONCE, REALM);
        return 438; // Stale Nonce rfc5389 10.2.2.
    }
    size_t user_len = ntohs(msg_user->length);
    if( user_len != strlen(USERNAME) ||
        0 != memcmp(msg_user->value, USERNAME, user_len) )
    {
        turn_unauthorize(client, NONCE, REALM);
        return 401; // Unauthorized rfc5389 10.2.2.
    }

    // message integrity check - rfc5389 15.4.4
    unsigned char *five_fields=
        __builtin_alloca(strlen(USERNAME)+strlen(REALM)+strlen(PASSWORD)+3);
    int  fields_len =
        sprintf((char*)five_fields, "%s:%s:%s", USERNAME, REALM, PASSWORD);
    unsigned char hmac_key[16];
    MD5(five_fields, fields_len, hmac_key);

    int slen = sizeof(stun_tlv_t) + ntohs(msg_integrity->length);
    int size = (int)((char*)msg_integrity - (char*)client->mseg) + slen;

    stun_hdr_t *hdr = __builtin_alloca(size);
    memcpy(hdr, client->mseg, size);

    // set length to include signature and no more
    hdr->length = htons(size - sizeof(stun_hdr_t));

    stun_tlv_t *tlv = (void*)((uint8_t*)hdr + size - slen);

    memset(tlv->value, 0, 20);

    hmac_sha1((uint8_t*)hdr, size - slen, hmac_key, 16, tlv->value);

    if( 0 != memcmp(tlv->value, msg_integrity->value, 20) )
    {
        turn_unauthorize(client, NONCE, REALM);
        return 401; // 401 to request, ignore to indications
    }

    return 0;  // no error
}

static void turn_affix_integrity(turnx_t *turnx, endpx_t *client)
{
    // message integrity - rfc5389 15.4.4
    unsigned char *five_fields =
        __builtin_alloca(strlen(USERNAME)+strlen(REALM)+strlen(PASSWORD)+3);
    int   fields_len =
         sprintf((char*)five_fields, "%s:%s:%s", USERNAME, REALM, PASSWORD);
    unsigned char hmac_key[16];
    MD5(five_fields, fields_len, hmac_key);

    stun_hdr_t *hdr = (void*)client->mout;
    int size = ntohs(hdr->length);
    stun_tlv_t *tlv = (void*)((uint8_t*)(hdr->attr) + size);

    int slen = sizeof(stun_tlv_t) + 20; // sha1

    // set length to include message integrity tlv
    hdr->length = htons(size + slen);

    size += sizeof(stun_hdr_t);

    tlv->type = htons(e_MESSAGE_INTEGRITY);
    tlv->length = htons(20);
    memset(tlv->value, 0, 20);
    hmac_sha1((uint8_t*)hdr, size, hmac_key, 16, tlv->value);
}

static int turn_allocate_request(turnx_t *turnx, endpx_t *client)
{
    LOGV("[%s:%u] allocate for %s:%u\n", __func__, __LINE__,
        inet_ntoa(client->from.sin_addr), ntohs(client->from.sin_port));

    // check integrity - rfc5389 10.2.2.
    int e = turn_check_integrity(turnx, client);

    if( e != 0 )
    {
        return e;
    }

    // search existing users
    int k;
    for( k = 0; k < TURN_CLIENTS_MAX; k++ )
    {
        userx_t *userx = turnx->userx + k;
        if( userx->allocated == 0 ) continue;
        if( client->from.sin_addr.s_addr == userx->client.sin_addr.s_addr
            && client->from.sin_port == userx->client.sin_port )
        {
            return e_TURN_ERROR_MISMATCH; // alread allocated - rfc5766 6.2.
        }
    }
    // check for REQUESTED-TRANSPORT
    if( 0 == turn_fetch_attribute(client->mseg,
                 client->mlen, e_TURN_REQUESTED_TRANSPORT, 0) )
    {
        return 400; // bad request - rfc5766 6.2.
    }
    if( turn_fetch_attribute(client->mseg,
            client->mlen, e_TURN_RESERVATION_TOKEN, 0) )
    {
        if( turn_fetch_attribute(client->mseg,
            client->mlen, e_TURN_EVEN_PORT, 0) )
        {
            return 400; // bad request - rfc5766 6.2.
        }
        // check token validity. return 508 as we don't support it yet
        return e_TURN_ERROR_CAPACITY;
    }
    for( k = 0; k < TURN_CLIENTS_MAX; k++ )
    {
        if( turnx->userx[k].allocated == 0 ) 
        {           
            break;
        }
    }
    if( k == TURN_CLIENTS_MAX )
    {
        return e_TURN_ERROR_QUOTA;
    }

    userx_t *userx = turnx->userx + k;
    endpx_t *relay = turnx->endpx + k;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    if( sock < 0 )
    {
        LOGI("[%s:%u] allocate error %d\n", __func__, __LINE__, errno);
        return e_TURN_ERROR_CAPACITY;
    }

    e = 1;
    e = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void*)&e, sizeof(e));

    struct sockaddr_in *sa = &(userx->relayed);
    memset(sa, 0, sizeof(*sa));
    sa->sin_family = AF_INET;
    sa->sin_addr = PEER_IF_ADDR;
    //sa->sin_addr.s_addr = inet_addr("172.20.20.20");;//inet_addr("192.168.127.9");

    e = bind(sock, (struct sockaddr *)sa, sizeof(*sa));

    if( e != 0 )
    {
        LOGI("[%s:%u] allocate error\n", __func__, __LINE__);
        return e_TURN_ERROR_CAPACITY;
    }

    socklen_t slen = sizeof(*sa);
    e = getsockname(sock, (struct sockaddr *)sa, &slen);

    if( e != 0 )
    {
        LOGI("[%s:%u] allocate error=%d\n", __func__, __LINE__, errno);
        return e_TURN_ERROR_CAPACITY;
    }

    relay->socket = sock;
    relay->mh->msg_name = &(relay->from);
    relay->mh->msg_namelen = sizeof(relay->from);
    relay->iov[0].iov_base = relay->mseg;
    relay->iov[0].iov_len = DATA_BUF_MAX;
    relay->mh->msg_iov = (relay->iov);
    relay->mh->msg_iovlen = 1;
    relay->mh->msg_control = relay->ctl;
    relay->mh->msg_controllen = sizeof(relay->ctl);

    // XOR-RELAYED-ADDRESS
    LOGV("[%s:%u] RELAYED_ADDRESS(userx[%d]) %s:%u\n", __func__, __LINE__,
        k, inet_ntoa(sa->sin_addr), ntohs(sa->sin_port));

    stun_map_t map={(0)};
    map.family = e_IPv4;
    map.port = sa->sin_port;
    *((struct in_addr*)(map.address)) = sa->sin_addr;
    map.port ^= htons(0x2112);
    *((uint32_t*)(map.address)) ^= htonl(0x2112A442);
    append_stun_attribute(client->mout, STUN_MSG_MAX, 
                            e_TURN_XOR_RELAYED_ADDRESS, 8, &map);

    // LIFETIME
    uint32_t ttl = htonl(TURN_RELAY_TTL);
    append_stun_attribute(client->mout, STUN_MSG_MAX, 
                            e_TURN_LIFETIME, 4, &ttl);

    // XOR-MAPPED-ADDRESS
    LOGV("[%s:%u] MAPPED_ADDRESS %s:%u\n", __func__, __LINE__,
        inet_ntoa(sa->sin_addr), ntohs(sa->sin_port));
    userx->client = client->from;
    sa = &(userx->client);
    map.port = sa->sin_port;
    *((struct in_addr*)(map.address)) = sa->sin_addr;
    map.port ^= htons(0x2112);
    *((uint32_t*)(map.address)) ^= htonl(0x2112A442);
    append_stun_attribute(client->mout, STUN_MSG_MAX, 
                            e_XOR_MAPPED_ADDRESS, 8, &map);

    // must include MESSAGE-INTEGRITY - rfc5389 10.2.2.
    turn_affix_integrity(turnx, client);

    // allocate
    userx->allocated = 1;
    userx->allocation_refreshed = turn_get_time();

    return 0;
}

static union {

    uint8_t tid[STUN_TID_SIZE];
    struct {
        unsigned long u8;
        unsigned int  u4;
    };
}   g_transction;

// @msg_class must be of enum stun_message_class
// @tid a 12-byte trasaction id 
static int  turn_create_message(uint8_t *msg, int size, int msg_method,
                                int msg_class, uint8_t *tid)
{
    if( size < sizeof(stun_hdr_t) ) return -1;
    
    stun_hdr_t *hdr = (void*)msg;
    
    memset(hdr, 0, sizeof(stun_hdr_t));
    
    hdr->type |= stun_method_to_u16(msg_method);
    hdr->type |= stun_class_to_u16(msg_class);

    hdr->type = htons(hdr->type);
    
    // Message Length not including the 20-byte STUN header
    hdr->length = 0;

    hdr->magic_cockie = htonl(0x2112A442);

    if( tid )
    {
        memcpy(hdr->transaction_id, tid, STUN_TID_SIZE);
    }
    else
    {
        g_transction.u8 += 1;
        memcpy(hdr->transaction_id, g_transction.tid, STUN_TID_SIZE);
    }
    
    return sizeof(stun_hdr_t);
}

static void turn_classify_message(uint8_t *msg, int msg_class)
{
    stun_hdr_t *hdr = (void*)msg;

    uint16_t type = ntohs(hdr->type);
    uint16_t method = stun_encode_method(type);

    type = 0;
    type |= stun_method_to_u16(method);
    type |= stun_class_to_u16(msg_class);

    hdr->type = htons(type);
}

// rfc5766 sec. 7.2.
static int  turn_client_refresh(turnx_t *turnx, endpx_t *client)
{
    // search existing users
    int k;
    for( k = 0; k < TURN_CLIENTS_MAX; k++ )
    {
        if( turnx->userx[k].allocated == 0 ) continue;
        if( client->from.sin_addr.s_addr == turnx->userx[k].client.sin_addr.s_addr
            && client->from.sin_port == turnx->userx[k].client.sin_port )
        {
            break;
        }
    }
    if( k == TURN_CLIENTS_MAX )
    {
        return e_TURN_ERROR_MISMATCH; // not yet allocated
    }

    // LIFETIME
    uint32_t ttl = htonl(TURN_RELAY_TTL);
    append_stun_attribute(client->mout, STUN_MSG_MAX, 
                            e_TURN_LIFETIME, 4, &ttl);

    userx_t *userx = turnx->userx + k;

    userx->allocation_refreshed = turn_get_time();

    return 0;
}

// rfc5766 sec. 9.2.
static int  turn_create_permission(turnx_t *turnx, endpx_t *client)
{
    uint8_t *msg = client->mseg;
    int len = client->mlen;

    // check integrity - rfc5389 10.2.2.
    int e = turn_check_integrity(turnx, client);

    if( e != 0 )
    {
        return e;
    }

    // search existing users
    int k;
    for( k = 0; k < TURN_CLIENTS_MAX; k++ )
    {
        userx_t *userx = turnx->userx + k;
        if( userx->allocated == 0 ) continue;
        if( client->from.sin_addr.s_addr == userx->client.sin_addr.s_addr
            && client->from.sin_port == userx->client.sin_port )
        {
            break;
        }
    }
    if( k == TURN_CLIENTS_MAX )
    {
        return e_TURN_ERROR_MISMATCH; // not yet allocated
    }

    stun_tlv_t *tlv=turn_fetch_attribute(msg, len, e_TURN_XOR_PEER_ADDRESS, 0);

    if( tlv == 0 || ntohs(tlv->length) < 8 )
    {
        LOGI("[%s:%u] missing e_TURN_XOR_PEER_ADDRESS\n", __func__, __LINE__);
        return 400; // Bad Request - rfc5766 sec 9.2.
    }

    userx_t *userx = turnx->userx + k;

    // fetch destination ip address
    stun_map_t *map = (void*)tlv->value;
    userx->mapped_peer[0] = *((uint32_t*)map->address);
    userx->mapped_peer[0] ^= htonl(0x2112A442);
    userx->permission_refreshed = turn_get_time();

    if( turn_fetch_attribute(msg, len, e_TURN_XOR_PEER_ADDRESS, tlv) )
    {
        LOGI("[%s:%u] too many e_TURN_XOR_PEER_ADDRESS\n", __func__, __LINE__);
        return 403; // more than 1 maps
    }

    // a blank response means permission granted
    // message integrity - rfc5766 section 4. rfc5389 10.2.2.
    turn_affix_integrity(turnx, client);

    return 0;
}

static int turn_send_msg(endpx_t *endpx, struct sockaddr_in *to,
                         uint8_t *msg, int len)
{
    int e = 0;

    if( len > 1472)
    {
        LOGI("[%s:%u] packet size (%u) exceeds MTU\n", __func__, __LINE__, len);
    }

    if( endpx->socket == -1 ) { e = len; goto exit; }

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
    memcpy(CMSG_DATA(cmsg), endpx->pin, sizeof(struct in_pktinfo));
    e = sendmsg(endpx->socket, &msgh, MSG_NOSIGNAL);
    if( e < 0 )
    {
        LOGI("[%s:%u] sent error errno=%d msg=%p len=%d\n",
            __func__, __LINE__, errno, msg, len);
        // [03/16/2021] if send() fails, just let session die
        close(endpx->socket);
        endpx->socket = -1;
    }

exit:

	return e;
}

// rfc5766 sec. 10.2.
static int  turn_send_indication(turnx_t *turnx, endpx_t *client)
{
    uint8_t *msg = client->mseg;
    int len = client->mlen;

    LOGV("[%s:%u] from %s:%u\n", __func__, __LINE__,
        inet_ntoa(client->from.sin_addr), ntohs(client->from.sin_port));
    // search existing users
    int k;
    for( k = 0; k < TURN_CLIENTS_MAX; k++ )
    {
        if( turnx->userx[k].allocated == 0 ) continue;
        if( client->from.sin_addr.s_addr == turnx->userx[k].client.sin_addr.s_addr
            && client->from.sin_port == turnx->userx[k].client.sin_port )
        {
            break;
        }
    }
    if( k == TURN_CLIENTS_MAX )
    {
        LOGV("[%s:%u] not yet allocated, discard\n", __func__, __LINE__);
        return 0; // not yet allocated, discard
    }

    stun_tlv_t * map = turn_fetch_attribute(msg, len, e_TURN_XOR_PEER_ADDRESS, 0);
    
    if( map == 0 || ntohs(map->length) != 8 ) // INET4
    {
        LOGV("[%s:%u] missing e_TURN_XOR_PEER_ADDRESS\n", __func__, __LINE__);
        return 0; // discard
    }

    stun_tlv_t * data = turn_fetch_attribute(msg, len, e_TURN_DATA, 0);
    
    if( data == 0 )
    {
        LOGV("[%s:%u] missing e_TURN_DATA\n", __func__, __LINE__);
        return 0; // discard
    }

    userx_t *userx = turnx->userx + k;

    struct sockaddr_in sa;
    memcpy(&sa, (void*)map->value, ntohs(map->length));
    sa.sin_family = AF_INET;
    sa.sin_port ^= htons(0x2112);
    sa.sin_addr.s_addr ^= htonl(0x2112A442);

    if( memcmp(&sa.sin_addr, &(userx->mapped_peer), 4) )
    {
        LOGV("[%s:%u] no permission mapping\n", __func__, __LINE__);
        return 0; // discard
    }

    turn_send_msg(turnx->endpx + k, &sa, data->value, ntohs(data->length));

    return 0;
}

// rfc5766 sec. 11.2.
static int turn_channel_bind(turnx_t *turnx, endpx_t *client)
{
    uint8_t *msg = client->mseg;
    int len = client->mlen;

    // search existing users
    userx_t *userx = 0;

    int k;
    for( k = 0; k < TURN_CLIENTS_MAX; k++ )
    {
        userx = turnx->userx + k;
        if( userx->allocated == 0 ) continue;
        if( client->from.sin_addr.s_addr == userx->client.sin_addr.s_addr
            && client->from.sin_port == userx->client.sin_port )
        {
            break;
        }
    }
    if( k == TURN_CLIENTS_MAX )
    {
        LOGI("[%s:%u] not yet allocated, discard\n", __func__, __LINE__);
        return e_TURN_ERROR_MISMATCH; // not yet allocated, discard
    }

    stun_tlv_t *chnl=turn_fetch_attribute(msg, len, e_TURN_CHANNEL_NUMBER, 0);

    if( chnl == 0 || ntohs(chnl->length) != 4 || chnl->value[0] < 0x40 )
    {
        LOGI("[%s:%u] missing CHANNEL-NUMBER\n", __func__, __LINE__);
        return 400; // Bad Request
    }

    int channel_number = ntohs(*(uint16_t*)chnl->value);

    int j;
    for( j = 0; j < TURN_CLIENTS_MAX; j++ )
    {
        if( j == k ) continue;
        if( turnx->userx[j].allocated == 0 ) continue;
        if( turnx->userx[j].channel_number == channel_number)
        {
            LOGI("[%s:%u] channel_number %d in use\n", __func__, __LINE__,
                channel_number);
            return 400; // Bad Request
        }
    }

    stun_tlv_t *peer=turn_fetch_attribute(msg, len, e_TURN_XOR_PEER_ADDRESS, 0);
    
    if( peer == 0 || ntohs(peer->length) != 8 ) // INET4
    {
        LOGI("[%s:%u] missing XOR_PEER_ADDRESS\n", __func__, __LINE__);
        return 400; // Bad Request
    }

    stun_map_t *map = (void *)peer->value;
    uint32_t mapped_peer =*(uint32_t *)map->address;
    mapped_peer ^= htonl(0x2112A442);
    if( userx->channel_number != 0 && userx->mapped_peer[0] != 0
        && userx->mapped_peer[0] != mapped_peer )
    {
        LOGV("[%s:%u] no more than one channel binding\n", __func__, __LINE__);
        return 400; // Bad Request
    }

    userx->channel_number = channel_number;
    userx->mapped_peer[0] = mapped_peer;
    userx->mapped_port[0] = map->port ^ htons(0x2112);
    userx->channel_refreshed = turn_get_time();

    // a blank response means channel binding granted

    return 0;
}

// rfc5766 sec 11.6
static int  channel_x_client(turnx_t *turnx, endpx_t *client)
{
    int channel_number = (client->mseg[0]<<8) + client->mseg[1];
    uint32_t channel_dlen = (client->mseg[2]<<8) + client->mseg[3];

    if( channel_dlen + 4 != client->mlen )
    {
        LOGV("[%s:%u] length mismatch\n", __func__, __LINE__);
        return 0;
    }

    // search existing users
     userx_t *userx = 0;
    int k;
    for( k = 0; k < TURN_CLIENTS_MAX; k++ )
    {
        if( userx->allocated == 0 ) continue;
        if( client->from.sin_addr.s_addr == userx->client.sin_addr.s_addr
            && client->from.sin_port == userx->client.sin_port )
        {
            break;
        }
    }
    if( k == TURN_CLIENTS_MAX )
    {
        LOGV("[%s:%u] not yet allocated, discard\n", __func__, __LINE__);
        return 0;
    }

    if( userx->channel_number != channel_number )
    {
        LOGV("[%s:%u] channel mismatch(%x %x), discard\n", __func__, __LINE__,
            userx->channel_number, channel_number);
        return 0;
    }
    
    if( userx->mapped_port[0] == 0 || userx->mapped_peer[0] == 0 )
    {
        LOGV("[%s:%u] bad mapped addr(%x) port(%x), discard\n", __func__, __LINE__,
            userx->mapped_port[0], userx->mapped_peer[0]);
        return 0;
    }

    struct sockaddr_in sa ={(0)};
    sa.sin_family = AF_INET;
    sa.sin_port = (uint16_t)(userx->mapped_port[0]);
    sa.sin_addr.s_addr = userx->mapped_peer[0];

    turn_send_msg(turnx->endpx + k, &sa, client->mseg + 4, channel_dlen);

    return 0;
}

static int  turn_from_client(turnx_t *turnx, endpx_t *client)
{
    uint8_t *msg = client->mseg;
    uint8_t *out = client->mout;
    int len = client->mlen;

    stun_hdr_t *hdr = (void*)msg;

    uint16_t type = ntohs(hdr->type);
    uint16_t method = stun_encode_method(type);
    if( (! stun_type_is_valid(type)) ||
        (! turn_class_is_valid(stun_message_class(type))) ||
        (! turn_method_is_valid(method)) )
    {
		// ignore
		LOGI("[%s:%u] type=%d %d %d %d invalid, ignore\n",
            __func__, __LINE__, type, stun_type_is_valid(type),
            turn_class_is_valid(stun_message_class(type)),
            turn_method_is_valid(stun_encode_method(type)) );
		return 0;
    }

    if( stun_message_class(type) == e_stun_class_request )
    {
        // initialize response
        turn_create_message(out, STUN_MSG_MAX, method,
                            e_stun_class_response, hdr->transaction_id);
    }

    int  error = 0;

    switch( method )
    {
    case e_stun_method_binding:
        error = turn_binding_request(client);
        break;
    case e_turn_method_allocate:
        error = turn_allocate_request(turnx, client);
        break;
    case e_turn_method_fefresh:
        error = turn_client_refresh(turnx, client);
        break;
    case e_turn_method_create_permission:
        error = turn_create_permission(turnx, client);
        break;
    case e_turn_method_send:
        error = turn_send_indication(turnx, client);
        break;
    case e_turn_method_channel_bind:
        error = turn_channel_bind(turnx, client);
        break;
    default:
        LOGI("[%s:%u] unknown method=%x\n", __func__, __LINE__, method);
        error = 400; // Bad Request
        break;
    }

    if( stun_message_class(type) != e_stun_class_request )
    {
        return 0; // no response
    }

    if( error != 0 )
    {
        LOGI("[%s:%u] error %d\n", __func__, __LINE__, error);
        if( error >= 300 && error < 700 )
        {
            turn_classify_message(out, e_stun_class_error);

            stun_err_t err={(0)};
            err.error_class = (error / 100);
            err.error_number = (error % 100);
            len = append_stun_attribute(out, STUN_MSG_MAX, 
                                        e_ERROR_CODE, 4, &err);
        }
        else
        {
            return 0;   // silently ignore this request
        }
    }

#if 0
    #define VENDOR "Ettaceo IVY"
    // sizeof(VENDER) includes trailing null
    len = append_stun_attribute(out, STUN_MSG_MAX, e_SOFTWARE,
                                sizeof(VENDOR), VENDOR);
#endif
    stun_tlv_t *tlv = 0;
    // rfc 5389 15.5
    // FINGERPRINT attribute MUST be the last attribute in the message
    hdr = (void*)out;
    len = ntohs(hdr->length);
    tlv= (void*)(out + sizeof(stun_hdr_t) + len);
    tlv->type = htons(e_FINGERPRINT);
    tlv->length = htons(sizeof(uint32_t));
    // update message length to include FINGERPRINT
    hdr->length = htons(len + sizeof(*tlv) + ntohs(tlv->length));
    // calcuate crc
    *(uint32_t*)(tlv->value) =
        htonl(0x5354554e^crc(out, sizeof(stun_hdr_t) + len));
    len = sizeof(stun_hdr_t) + ntohs(hdr->length);

    return len;
}

// rfc5766 sec. 10.3.
static int turn_from_peer(turnx_t *turnx, endpx_t *endpx)
{
    struct sockaddr_in *sa = &(endpx->from);

    LOGV("[%s:%u] from %s:%u\n", __func__, __LINE__,
        inet_ntoa(sa->sin_addr), ntohs(sa->sin_port));

    // search existing users
    userx_t *userx = 0;
    int k;
    for( k = 0; k < TURN_CLIENTS_MAX; k++ )
    {
        userx = turnx->userx + k;
        if( userx->allocated == 0 ) continue;
        if( userx->mapped_peer[0] ==  sa->sin_addr.s_addr &&
            (userx->channel_number == 0 ||
             userx->mapped_port[0] == sa->sin_port) )
        {
            break;
        }
    }
    
    if( k == TURN_CLIENTS_MAX )
    {
        LOGI("[%s:%u] no permission mapping\n", __func__, __LINE__);
        return 0; // no mapping
    }

    // check there is channel bound
    if( userx->channel_number != 0 )
    {
        *(uint16_t*)(endpx->head+0) = htons(userx->channel_number);
        *(uint16_t*)(endpx->head+2) = htons(endpx->mlen);
        // send over channel
        turn_send_msg(turnx->endpx + TURN_CLIENTS_MAX,
                      &(userx->client),
                      endpx->head, endpx->mlen + 4);
        return 0;
    }

    // create turn data inidcation
    uint8_t *out = endpx->mout;
    int len = turn_create_message(out, STUN_MSG_MAX, e_turn_method_data,
                                  e_stun_class_inidication, 0);
    // XOR-PEER-ADDRESS
    stun_map_t map={(0)};
    map.family = e_IPv4;
    map.port = sa->sin_port;
    *((struct in_addr*)(map.address)) = sa->sin_addr;

    map.port ^= htons(0x2112);
    *((uint32_t*)(map.address)) ^= htonl(0x2112A442);
    len = append_stun_attribute(out, STUN_MSG_MAX, 
                                e_TURN_XOR_PEER_ADDRESS, 8, &map);

    // DATA
    len = append_stun_attribute(out, STUN_MSG_MAX, e_TURN_DATA,
                                endpx->mlen, endpx->mseg);
    // send out
    len = turn_send_msg(turnx->endpx + TURN_CLIENTS_MAX,
                        &(userx->client),
                        out, len);
    return 0;
}

////////////////////////////////////////////////////////////////////////
#ifdef LOCAL_BUILD

void * turn_thread(void *ctx)
{
    turnx_t *turnx = ctx;
    int    e, i; 

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
   
    if( sock == -1 )
    {
        LOGI("[%s:%u] socket() error\n", __func__, __LINE__);
        return 0;
    }

    e = 1;
    e = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void*)&e, sizeof(e));

    struct sockaddr_in sa={(0)};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(turnx->turn_port);

    e = bind(sock, (struct sockaddr *)&sa, sizeof(sa));

    if( e != 0 )
    {
        LOGI("[%s:%u] bind() error\n", __func__, __LINE__);
        return 0;
    }

    e = 1;
    e = setsockopt(sock, IPPROTO_IP, IP_PKTINFO, &e, sizeof(e));
    
    endpx_t *endpx = turnx->endpx + TURN_CLIENTS_MAX;
    endpx->socket = sock;
    endpx->mh->msg_name = &(endpx->from);
    endpx->mh->msg_namelen = sizeof(endpx->from);
    endpx->iov[0].iov_base = endpx->mseg;
    endpx->iov[0].iov_len = DATA_BUF_MAX;
    endpx->mh->msg_iov = (endpx->iov);
    endpx->mh->msg_iovlen = 1;
    endpx->mh->msg_control = endpx->ctl;
    endpx->mh->msg_controllen = sizeof(endpx->ctl);

    while( ! turnx->quit[0] )
    {
        struct pollfd fds[TURN_CLIENTS_MAX+1]={(0)};

        for( i = 0; i <= TURN_CLIENTS_MAX; i++)
        {
            fds[i].fd = turnx->endpx[i].socket;  // can be -1
            fds[i].events = POLLIN;
            fds[i].revents = 0;
        }

        e = poll(fds, TURN_CLIENTS_MAX+1, SOCKET_POLL_INTERVAL);

        if( e > 0 ) for( i = 0; i <= TURN_CLIENTS_MAX; i++)
        {
            if( !(fds[i].revents & POLLIN) ) continue;

            endpx_t *endpx = turnx->endpx + i;

            endpx->mlen = 0; // clear message buffer

            endpx->mh->msg_flags = 0;
            e = recvmsg(endpx->socket, endpx->mh, 0);

            if( e > 0 )
            {
                endpx->mlen = e;
                get_pkt_info(endpx, endpx->pin);
                if( i == TURN_CLIENTS_MAX )
                {
                    // rfc5766 sec. 11. check high 2 bits
                    if( endpx->mseg[0] & 0xc0 )
                    {
                        e = channel_x_client(turnx, endpx);
                    }
                    else
                    {
                        e = turn_from_client(turnx, endpx);
                    }
                }
                else
                {
                    e = turn_from_peer(turnx, endpx);
                }
                if( e > 0 )
                {
                    e = turn_send_msg(endpx, &endpx->from, endpx->mout, e);
                }
            }
        }

        // connectivity check
        int  now = turn_get_time();
        for( i = 0; i < TURN_CLIENTS_MAX; i++)
        {
            userx_t *userx = turnx->userx + i;
            endpx_t *endpx = turnx->endpx + i;
            if( userx->allocated == 0 ) continue;
            if( (endpx->socket != -1) &&
                (now - userx->allocation_refreshed) > TURN_RELAY_TTL )
            {
                LOGI("[%s:%u] client %d timeout\n", __func__, __LINE__, i);

                turn_halt_client(turnx, i);
            }
            
            if( userx->mapped_peer[0] == 0 ) continue;
            if( userx->channel_number != 0 &&
                (now - userx->channel_refreshed) > TURN_CHANNEL_TTL )
            {
                LOGI("[%s:%u] channel expired (index=%d)\n", __func__, __LINE__, i);
                userx->mapped_peer[0] = 0; // expired
                userx->mapped_port[0] = 0;
                userx->channel_number = 0;
            }
            else if( (now - userx->permission_refreshed) > TURN_PERMISSION_TTL )
            {
                LOGI("[%s:%u] permission expired (index=%d)\n", __func__, __LINE__, i);
                userx->mapped_peer[0] = 0; // expired
                userx->mapped_port[0] = 0;
            }
        }
    }
    LOGV("[%s:%u] quit=%d\n", __func__, __LINE__, turnx->quit[0]);

    for( i = 0; i < TURN_CLIENTS_MAX; i++)
    {
        if( turnx->endpx[i].socket != -1 ) turn_halt_client(turnx, i);
    }

    close(turnx->endpx[TURN_CLIENTS_MAX].socket);

    turnx->endpx[TURN_CLIENTS_MAX].socket = -1;

    return 0;
}

static int g_quit;
static void sig_int(int sig)
{
    g_quit = 1;
}

int main(int argc, char *argv[])
{
    if( argc < 4 )
    {
        //printf("Usage:\t%s <user>:<pass>\n", argv[0]);
        printf("Usage:\t%s user=<user> pass=<pass> peer-if=<ip>\n", argv[0]);
        return 0;
    }
    const char *user=0, *pass=0, *peerif=0;
    int k;
    for( k = 1; k < argc; ++k )
    {
        if( 0 == strncmp(argv[k], "user=", 5) )
        {
            user = argv[k] + 5; continue;
        }
        if( 0 == strncmp(argv[k], "pass=", 5) )
        {
            pass = argv[k] + 5; continue;
        }
        if( 0 == strncmp(argv[k], "peer-if=", 8) )
        {
            peerif = argv[k] + 8;
        }
    }

    if( setup_credential(user, pass) != 0 )
    {
        printf("Invalid user/pass combination!\n");
        return 0;
    }

    if( set_peer_net_if(peerif) != 0 )
    {
        printf("Invalid peer interface!\n");
        return 0;
    }

    signal(SIGINT, sig_int);

    turnx_t *turnx = __builtin_malloc(sizeof(turnx_t));

    memset(turnx, 0, sizeof(turnx_t));

    turnx->quit = &g_quit;

    int e, i;

    for( i = 0; i < TURN_CLIENTS_MAX; i++)
    {
        turnx->endpx[i].socket = -1;
    }

    turnx->turn_port = STUN_PORT;

    pthread_t turn_task;

    // create a ice agent thread
    e = pthread_create(&turn_task, 0, turn_thread, turnx);

    if(e == 0) pthread_join(turn_task, 0);

    return 0;
}

#endif // LOCAL_BUILD
