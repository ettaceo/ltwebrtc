// file : stun5389.c
// date : 11/28/2019
//
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "stun5389.h"
#include "cryptlib/crc.h"
#include "cryptlib/hmac.h"

#define LOGV(...)
#define LOGI(...)
//#define LOGV printf
//#define LOGI printf

// weak version for unit test
 __attribute__((weak))
void * sip_query_ufrag(uint8_t *name, int len)
{
    return 0;
}

__attribute__((weak))
void ice_use_candidate(void *sess, int val)
{
}

__attribute__((weak))
void  session_keepalive(void *sess)
{
}

__attribute__((weak))
void * ice_session_peer(void *sess)
{
    return 0;
}

//
// as per rfc8445 section 7.2.2 usename consists of two part:
//   server-side-name:client-side-name
// it is possible client-side-name is unknown at the time stun binding
// request is received (it is sent via client sdp offer/answer)
// as per rfc8445 section 7.3. use server-side-name to match password
// for message integrity check
//
void * stun_query_user(stun_tlv_t *user)
{
    // rfc 8445 sec 7.3. use first part of the usename to match password
    return sip_query_ufrag(user->value,  ntohs(user->length));
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
int  create_stun_message(uint8_t *msg, int size,
                         int msg_class, uint8_t *tid)
{
    if( size < sizeof(stun_hdr_t) ) return -1;
    
    stun_hdr_t *hdr = (void*)msg;
    
    memset(hdr, 0, sizeof(stun_hdr_t));
    
    hdr->type |= stun_method_to_u16(e_stun_method_binding);
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

// @length can be zero; in that case @value is ignored
int  append_stun_attribute(uint8_t *msg, int size,
                           int attr_type, int length, void *value)
{
    if( size < sizeof(stun_hdr_t) ) return -1;

    // rfc5389 section 15: 
    // Each STUN attribute MUST end on a 32-bit boundary
    if( length % 4 ) return -1;
    
    stun_hdr_t *hdr = (void*)msg;

    int msg_len = sizeof(stun_hdr_t) + ntohs(hdr->length);
    
    stun_tlv_t *tlv = (void*)(msg + msg_len);
    
    msg_len += sizeof(stun_tlv_t) + length;
    
    if( msg_len > size ) return -2;  // buffer overflow

    tlv->type = htons(attr_type);
    tlv->length = htons(length);
    if( length > 0 ) memcpy(tlv->value, value, length);
    
    hdr->length = htons(msg_len - sizeof(stun_hdr_t));
    
    return msg_len;
}

// for list of registered attributes:
// https://www.iana.org/assignments/stun-parameters/stun-parameters.xhtml
void * get_next_attribute(uint8_t *msg, int size, void *tlv)
{
    if( size <= sizeof(stun_hdr_t) ) return 0;
    
    if( tlv == 0 )
    {
        stun_hdr_t *hdr = (void*)msg;
    
        int msg_len = sizeof(stun_hdr_t) + ntohs(hdr->length);

        if( msg_len > size ) return 0;

        return (msg_len > 0 ? hdr->attr : 0);
    }
    // rfc5389 section 15. attribute spacemust be 4-byte aligned
    int alen = sizeof(stun_tlv_t) + ntohs(((stun_tlv_t*)tlv)->length);
    if( alen & 0x03 ) alen += 4 - (alen & 0x03 );

    uint8_t *nxt = (uint8_t*)tlv + alen;

    if( (int)((uint8_t*)nxt - (uint8_t*)msg) < size )
    {
        return nxt;
    }

    return 0;
}

int stun_check_signature(uint8_t *msg, stun_tlv_t *sign,
                        stun_tlv_t *user, uint8_t *pwd)
{
    if( user == 0 ) return 400; // rfc5389 sec 10.1.2.
    
    if( pwd == 0 ) return 401; // rfc5389 sec 10.1.2.
        
    // check signature
    int slen = sizeof(stun_tlv_t) + ntohs(sign->length);
    int size = (int)((char*)sign - (char*)msg) + slen;
        
    stun_hdr_t *hdr = __builtin_alloca(size);
    memcpy(hdr, msg, size);

    // set length to include signature and no more
    hdr->length = htons(size - sizeof(stun_hdr_t));

    stun_tlv_t *tlv = (void*)((uint8_t*)hdr + size - slen);
    
    memset(tlv->value, 0, 20);

    hmac_sha1((uint8_t*)hdr, size - slen, pwd, strlen((char*)pwd), tlv->value);

    if( 0 != memcmp(tlv->value, sign->value, ntohs(sign->length)) )
    {
        LOGV("[%s:%u] signature incorrect\n", __func__, __LINE__);
        return 401; // 401 to request, ignore to indications
    }

    return 0;  // no error
}

int stun_check_fingerprint(uint8_t *msg, stun_tlv_t *tlv)
{
    int mlen = (int)((uint8_t*)tlv - msg);
    int size = mlen + sizeof(stun_tlv_t) + 4;
    
    stun_hdr_t *hdr = __builtin_alloca(size);
    
    memcpy(hdr, msg, size);
    // set length to include fingerprint tlv
    hdr->length = htons(size - sizeof(stun_hdr_t));

    uint32_t stun_crc = (0x5354554e^crc((void*)hdr, mlen));
    
    return (stun_crc - ntohl(*(unsigned int*)(tlv->value)));
}

extern void * ice_session_peer(void *sess);
extern void  session_keepalive(void *sess);
extern void  ice_use_candidate(void *sess, int val);

int  stun_service(void *msg, int len, void *sess)
{
    struct sockaddr_in *sa = ice_session_peer(sess);
    LOGI("[%s:%u] stun %d from src %s:%u\n", __func__, __LINE__,
         len, inet_ntoa(sa->sin_addr), ntohs(sa->sin_port));

    stun_hdr_t *hdr = (void*)msg;

    int type = ntohs(hdr->type);
    if( ! stun_type_is_valid(type) 
        || stun_message_class(type) != e_stun_class_request 
        || stun_encode_method(type) != e_stun_method_binding)
    {
		// ignore
		LOGI("[%s:%u] type=%d not a binding request, ignore\n",
            __func__, __LINE__, type);
		return 0;
    }
    int32_t  ice_priority=-1;  // rfc8445 (-1) is not a valid priority
    int  ice_candidate=0;
    // draft-ietf-mmusic-ice-sip-sdp: 
    // offerer being  controlling, answerer being controlled
    int  ice_role=e_ICE_ROLE_UNKNOWN;
    int  crc_ok=1;
    stun_tlv_t *user=0;
    stun_tlv_t *tlv = 0;
    uint8_t *pwd = 0;
    int  error = 0;
    while( error==0 && (tlv = get_next_attribute(msg, len, tlv)) )
    {
        int size = ntohs(tlv->length);
        switch( (type = ntohs(tlv->type)) )
        {
        case e_USERNAME:
            user = tlv; // save username for e_MESSAGE_INTEGRITY
            LOGV("[%s:%u] username(%#x, %d) %.*s\n", __func__, __LINE__,
                type, size, size, tlv->value);
            pwd = stun_query_user(user);
            if( pwd == 0 ) error = 401;
            break;
        case e_MESSAGE_INTEGRITY:
	   	    LOGV("[%s:%u] message-integrity(%#x %d)\n", __func__, __LINE__, 
                type, size);
            error = stun_check_signature(msg, tlv, user, pwd);
            LOGV("[%s:%u] signature(%#x %d) %s\n", __func__, __LINE__,
                type, size, error?"error":"ok");
            break;
        case e_PRIORITY:
            // priority
            ice_priority = ntohl(*(unsigned int*)(tlv->value));
	   	    LOGV("[%s:%u] priority(%#x %d) val=%u\n", __func__, __LINE__, 
                type, size, ice_priority);
            break;
        case e_USE_CANDIDATE:
            LOGV("[%s:%u] USE-CANDIDATE(%#x %d)\n", __func__, __LINE__,
                type, size);
            ice_candidate = 1;
            break;
        case e_FINGERPRINT:
            // FINGERPRINT - crc for stun message so far rfc5389 sec 15.5
            // rfc5389 section 7.3. silently discard
            crc_ok = (stun_check_fingerprint(msg, tlv) == 0);
            error = ( crc_ok ? 0 : 1 );
	   	    LOGV("[%s:%u] fingerprint(%#x %d) %s\n", __func__, __LINE__,
                type, size, crc_ok? "ok" : "bad");
            break;
        case e_ICE_CONTROLLED:
            ice_role = e_ICE_ROLE_CONTROLLED;
	   	    LOGV("[%s:%u] ice-controlled(%#x %d)\n", __func__, __LINE__, 
                type, size);
            break;
        case e_ICE_CONTROLLING:
            ice_role = e_ICE_ROLE_CONTROLLING;
	   	    LOGV("[%s:%u] ice-controlling(%#x %d)\n", __func__, __LINE__, 
                type, size);
            break;
        default:
	   	    LOGV("[%s:%u] attribute(%#x %d)\n", __func__, __LINE__, 
                type, size);
            break;
        }
        (void)size; // to supress compiler complaints
    }

    // initialize response
    uint8_t tid[STUN_TID_SIZE];
    memcpy(tid, hdr->transaction_id, STUN_TID_SIZE);
    len = create_stun_message(msg, STUN_MSG_MAX, e_stun_class_response, tid);

    if( ice_candidate == 0 )
    {
    }
    ice_use_candidate(sess, ice_candidate);

    if( error != 0 )
    {
        LOGI("[%s:%u] parsing error %d\n", __func__, __LINE__, error);
        if( error >= 300 && error < 700 )
        {
            stun_err_t err={(0)};
            err.error_class = (error / 100);
            err.error_number = (error % 100);
            len = append_stun_attribute(msg, STUN_MSG_MAX, 
                                        e_ERROR_CODE, 4, &err);
            goto exit;
        }
        return 0;   // silently ignore this request
    }

    stun_map_t map={(0)};
    // e_MAPPED_ADDRESS
    map.family = e_IPv4;
    map.port = sa->sin_port;
    *((struct in_addr*)(map.address)) = sa->sin_addr;
LOGI("[%s:%u] map.address %s:%u\n", __func__, __LINE__, inet_ntoa(sa->sin_addr), ntohs(sa->sin_port));
#if 0
    len = append_stun_attribute(msg, STUN_MSG_MAX, e_MAPPED_ADDRESS, 8, &map);
#endif
    map.family = e_IPv4;
    map.port ^= htons(0x2112);
    *((uint32_t*)(map.address)) ^= htonl(0x2112A442);
    len = append_stun_attribute(msg, STUN_MSG_MAX, 
                                e_XOR_MAPPED_ADDRESS, 8, &map);

    hdr = (void*)msg;
    int mlen = 0;

    // if request is for connectivity check
    if( ice_priority != -1 && ice_role != e_ICE_ROLE_UNKNOWN )
    {
        LOGV("[%s:%u] connectivity check\n", __func__, __LINE__);
        session_keepalive(sess);  // update icep session last_checked
        // add USE-CANDIDATE
//        len = append_stun_attribute(msg, STUN_MSG_MAX, 
//                                e_USE_CANDIDATE, 0, 0);
        // add message-integrity
        mlen = ntohs(hdr->length); //
        tlv = (void*)(msg + sizeof(stun_hdr_t) + mlen);
        tlv->type = htons(e_MESSAGE_INTEGRITY);
        tlv->length = htons(20);
        // update message length to include MESSAGE_INTEGRITY
        hdr->length = htons(mlen + sizeof(*tlv) + ntohs(tlv->length));
        hmac_sha1(msg, sizeof(stun_hdr_t) + mlen, 
                pwd, strlen((char*)pwd), tlv->value);
        len = sizeof(stun_hdr_t) + ntohs(hdr->length);
    }

exit:
#if 0
    #define VENDOR "Ettaceo IVY"
    // sizeof(VENDER) includes trailing null
    len = append_stun_attribute(msg, STUN_MSG_MAX, e_SOFTWARE,
                                sizeof(VENDOR), VENDOR);
#endif
    // rfc 5389 15.5
    // FINGERPRINT attribute MUST be the last attribute in the message
    mlen = ntohs(hdr->length);
    tlv= (void*)(msg + sizeof(stun_hdr_t) + mlen);
    tlv->type = htons(e_FINGERPRINT);
    tlv->length = htons(sizeof(uint32_t));
    // update message length to include FINGERPRINT
    hdr->length = htons(mlen + sizeof(*tlv) + ntohs(tlv->length));
    // calcuate crc
    *(uint32_t*)(tlv->value) =
        htonl(0x5354554e^crc(msg, sizeof(stun_hdr_t) + mlen));
    len = sizeof(stun_hdr_t) + ntohs(hdr->length);

    return len;
}

// retrieve mapped address from stun response
int get_stun_address(uint8_t *msg, int len, uint32_t *ipv4, uint16_t *port)
{
    stun_tlv_t *tlv=0;
    stun_map_t *map;
    struct sockaddr_in sa={(0)};

    // test if a success response - rfc5389 sec 6.
    if( ! (msg[0] & 0x01) || (msg[1]&0x10) )
    {
        LOGV("[%s:%u] fail response\n", __func__, __LINE__);
        goto exit;
    }

    while( (tlv = get_next_attribute(msg, len, tlv)) )
    {
        map = 0;
        switch(ntohs(tlv->type))
        {
        case e_MAPPED_ADDRESS:
            map = (void*)tlv->value;
            sa.sin_addr.s_addr = *(uint32_t*)(map->address);
            sa.sin_port = map->port;
            LOGV("e_MAPPED_ADDRESS: %s:%u\n", inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));
            break;
        case e_XOR_MAPPED_ADDRESS:
        case ex_XOR_MAPPED_ADDRESS:
            map = (void*)tlv->value;
            sa.sin_addr.s_addr = *(uint32_t*)(map->address);
            sa.sin_addr.s_addr ^= htonl(0x2112A442);  // rfc 15.2
            sa.sin_port = (map->port^htons(0x2112));  // rfc 15.2
            LOGV("e_XOR_MAPPED_ADDRESS: %s:%u\n", inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));
            break;
        default:
            break;
        }
        if( map ) break;
    }
exit:
    if( ipv4 ) *ipv4 = sa.sin_addr.s_addr;
    if( port ) *port = ntohs(sa.sin_port);

    return 0;
}
