// file : stun5389.h
// date : 11/28/2019
#ifndef STUN5389_H_
#define STUN5389_H_

#include <stdint.h>

#define STUN_MSG_MAX 1024

// rfc5389 section 18.4
#define STUN_PORT 3478

// rfc5389 section 6
enum stun_message_classes
{
    e_stun_class_request=0,
    e_stun_class_inidication=1,
    e_stun_class_response=2,
    e_stun_class_error=3
};

// rfc5389 section 6
enum stun_encoding_methods
{
    e_stun_method_binding = 0x0001,   // binding
    e_stun_method_max
};

// rfc5389 section 18.2
enum stun_attributes
{
    e_MAPPED_ADDRESS=0x0001,
    e_RESPONSE_ADDRESS=0x0002,
    e_CHANGE_ADDRESS=0x0003,
    e_SOURCE_ADDRESS=0x0004,
    e_CHANGED_ADDRESS=0x0005,
    e_USERNAME=0x0006,
    e_MESSAGE_INTEGRITY=0x0008,
    e_ERROR_CODE=0x0009,
    e_UNKNOWN_ATTRIBUTES=0x000A,
    e_REALM=0x0014,
    e_NONCE=0x0015,
    e_PRIORITY=0x0024,
    e_USE_CANDIDATE=0x0025,
    
    e_XOR_MAPPED_ADDRESS=0x0020,
    ex_XOR_MAPPED_ADDRESS=0x8020, // draft-ietf-behave-rfc3489bis-02

    e_SOFTWARE=0x8022,
    e_ALTERNATE_SERVER=0x8023,
    e_FINGERPRINT=0x8028,
    e_ICE_CONTROLLED=0x8029,
    e_ICE_CONTROLLING=0x802A,
    
    e_ATTRIBUTE_MAX
};

// rfc5389 section 15.1
enum stun_address_family
{
    e_IPv4 = 0x01,
    e_IPv6 = 0x02
};

// rfc8445
enum stun_ice_role
{
    e_ICE_ROLE_UNKNOWN,
    e_ICE_ROLE_CONTROLLED,
    e_ICE_ROLE_CONTROLLING
};

// @t of uint16_t type in host order
#define stun_type_is_valid(t) (!((t)&0xc000))
#define stun_message_class(t) ((((t)&0x0100)>>7)|(((t)&0x10)>>4))
#define stun_encode_method(t) ((((t)&0x3e00)>>2)|(((t)&0xc0)>>1)|((t)&0x0f))
// @m of uint16_t type in host order
#define stun_method_to_u16(m) ((((m)&0x3e00)<<2)|(((m)&0xc0)<<1)|((m)&0x0f))
// @c of uint16_t type in host order
#define stun_class_to_u16(c)  ((((c)&0x2)<<7)|(((c)&0x1)<<4))

// as per rfc-5389 section 15 attributes
typedef struct stun_tlv_t
{
    uint16_t   type;
    uint16_t   length;
    uint8_t    value[0];  // 4-byte aligned
    
}   stun_tlv_t;

#define STUN_TID_SIZE 12

// as per rfc-5389 section 6
typedef struct stun_hdr_t
{
    uint16_t   type;  // STUN Message Type
    uint16_t   length; // not including STUN header (20 bytes)
    uint32_t   magic_cockie;   // htonl(0x2112A442)
    uint8_t    transaction_id[STUN_TID_SIZE];
    stun_tlv_t attr[0];

}   stun_hdr_t;

// as per rfc-5389 section 15.1
typedef struct stun_map_t
{
    uint8_t   zero;
    uint8_t   family;
    uint16_t  port;
    uint8_t   address[16]; // 4 bytes for ipv4
    
}   stun_map_t;

typedef struct stun_err_t
{
    uint16_t zero;
    uint8_t  error_class;  // 3-bit 3-6
    uint8_t  error_number; // 0-99
    uint8_t  text[0];
    
}   stun_err_t;

#ifdef __cplusplus
extern "C" {
#endif

void *stun_query_user(stun_tlv_t *user);

int   stun_check_fingerprint(uint8_t *msg, stun_tlv_t *tlv);
int   stun_check_signature(uint8_t *msg, stun_tlv_t *sign,
                           stun_tlv_t *user, uint8_t *pwd);

int   stun_service(void *msg, int len, void *src);

int   create_stun_message(uint8_t *msg, int size, 
                          int msg_class, uint8_t tid[12]);

int   append_stun_attribute(uint8_t *msg, int size,
                            int attr_type, int length, void *value);

void *get_next_attribute(uint8_t *msg, int size, void *tlv);

int   get_stun_address(uint8_t *msg, int len, uint32_t *ipv4, uint16_t *port);

#ifdef __cplusplus
}
#endif

#endif // STUN5389_H_
