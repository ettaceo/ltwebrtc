// file : turn5766.h
// date : 02/10/2023
#ifndef TURN5766_H_
#define TURN5766_H_

#include "stun5389.h"

// rfc5766 section 13.
enum turn_encoding_methods
{
    e_turn_method_allocate = 0x0003,
    e_turn_method_fefresh = 0x0004,
    e_turn_method_send = 0x0006,
    e_turn_method_data = 0x0007,
    e_turn_method_create_permission = 0x0008,
    e_turn_method_channel_bind = 0x0009,
    e_turn_method_max
};

// rfc5766 section 14.
enum turn_attributes
{
    e_TURN_CHANNEL_NUMBER=0x000C,
    e_TURN_LIFETIME=0x000D,
    e_TURN_RESERVED1=0x0010, // BANDWIDTH
    e_TURN_XOR_PEER_ADDRESS=0x0012,
    e_TURN_DATA=0x0013,
    e_TURN_XOR_RELAYED_ADDRESS=0x0016,
    e_TURN_REQUESTED_ADDRESS_FAMILY=0x0017, // rfc8656
    e_TURN_EVEN_PORT=0x0018,
    e_TURN_REQUESTED_TRANSPORT=0x0019,
    e_TURN_DONT_FRAGMENT=0x001A,
    e_TURN_RESERVED2=0x0021, // TIMER_VAL
    e_TURN_RESERVATION_TOKEN=0x0022,
    e_TURN_ADDITIONAL_ADDRESS_FAMILY=0x8000, // rfc8656
    e_TURN_ADDRESS_ERROR_CODE=0x8001, // rfc8656
    e_TURN_ICMP=0x8004, // rfc8656
    e_TURN_ATTRIBUTE_MAX
};

// rfc5766 section 15.
enum turn_error_codes
{
    e_TURN_ERROR_FORBIDDEN=403,
    e_TURN_ERROR_MISMATCH=437,
    e_TURN_ERROR_CREDENTIALS=441,
    e_TURN_ERROR_PROTOCOL=442,
    e_TURN_ERROR_QUOTA=486,
    e_TURN_ERROR_CAPACITY=508,
    e_TURN_ERROR_MAX
};

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#endif // TURN5766_H_
