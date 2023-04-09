// file : dtls5764.h dtls6347.h
// date : 01/11/2020 12/01/2019
#ifndef DTLS6347_H_
#define DTLS6347_H_
//
// references:
//   RFC-5246  TLS 1.2
//   RFC-5764  DTLS-SRTP
//   RFC-6347  DTLS
//
#include <stdint.h>

// 1-byte type + 2-byte version + 2-byte length
#define TLS_REC_HEADER_SIZE 5

// 1-byte type + 2-byte version + 8-byte ? + 2-byte length
#define DTLS_REC_HEADER_SIZE 13

#define DTLS_MESSAGE_MAX (1<<14)

typedef struct tls_vla1_t
{
    uint8_t  max;
    uint8_t  len;  // <0..2^8>
    uint8_t  val[0];

}   tls_vla1_t;

typedef struct tls_vla2_t
{
    uint16_t max;
    uint16_t len;  //<0..2^16>
    uint8_t  val[0];

}   tls_vla2_t;

typedef struct dtls_rechdr_t
{
    uint8_t content_type;
    uint8_t protocol_version[2];
    uint8_t epoch[2];
    uint8_t sequence_number[6];
    uint8_t length[2];

}   dtls_rechdr_t;


// must match srtp profile in select_srtp_profile()
// rfc7714 section 12. AEAD_AES_256_GCM
//#define SRTP_MASTER_KEY_LENGTH  32 // AEAD_AES_256_GCM
#define SRTP_MASTER_KEY_LENGTH  16 // AEAD_AES_128_GCM
#define SRTP_MASTER_SALT_LENGTH 14

// rfc5246 sec 6.3.
#define TLS_ENC_KEY_LENGTH   16   // rfc5116 (5.1.)
#define TLS_FIXED_IV_LENGTH  4    // rfc5288 (3.)
#define TLS_RECORD_IV_LENGTH 8    // rfc5288 (3.)
#define TLS_GCM_TAG_LENGTH   16   // rfc5116 (5.3.)
#define VERIFY_DATA_LENGTH   12   // rfc5246 7.4.9. "12 octets"

// rfc5246 section 7.2.
enum tls_alert_description
{
	e_close_notify=(0),
    e_unexpected_message=(10),
    e_bad_record_mac=(20),
    e_decryption_failed_RESERVED=(21),
    e_record_overflow=(22),
    e_decompression_failure=(30),
    e_handshake_failure=(40),
    e_no_certificate_RESERVED=(41),
    e_bad_certificate=(42),
    e_unsupported_certificate=(43),
    e_certificate_revoked=(44),
    e_certificate_expired=(45),
    e_certificate_unknown=(46),
    e_illegal_parameter=(47),
    e_unknown_ca=(48),
    e_access_denied=(49),
    e_decode_error=(50),
    e_decrypt_error=(51),
    e_export_restriction_RESERVED=(60),
    e_protocol_version=(70),
    e_insufficient_security=(71),
    e_internal_error=(80),
    e_user_canceled=(90),
    e_no_renegotiation=(100),
    e_unsupported_extension=(110),
    e_alert_desciption_max=(255)
};
// client hello strucs

// rfc5246 (6.2.1.) ProtocolVersion
typedef struct tls_protocol_version_t
{
    uint8_t major;
    uint8_t minor;

}  tls_protocol_version_t;

// rfc5246 (6.2.1.) ContentType
enum tls_content_type 
{
    e_change_cipher_spec=20,
    e_alert=21, 
    e_handshake=22,
    e_application_data=23,
    e_content_type_max=255
};

// rfc5246 (7.1.)
enum tls_handshake_type
{
    e_hello_request=0, 
    e_client_hello=1,
    e_server_hello=2,
    e_session_ticket=4,  // rfc5077 (3.3.) 3rd paragraph
    e_certificate=11,
    e_server_key_exchange=12,
    e_certificate_request=13,
    e_server_hello_done=14,
    e_certificate_verify=15,
    e_client_key_exchange=16,
    e_finished=20,
    e_handshake_max=255
};

// rfc5246 (7.4.4.)
enum tls_certificate_type
{
    e_rsa_sign=1,
    e_dss_sign=2,
    e_rsa_fixed_dh=3,
    e_dss_fixed_dh=4,
    e_rsa_ephemeral_dh_RESERVED=5,
    e_dss_ephemeral_dh_RESERVED=6,
    e_fortezza_dms_RESERVED=20,
    e_ecdsa_sign=64, // rfc4492 5.5.
    e_rsa_fixed_ecdh=65, // rfc4492 5.5.
    e_ecdsa_fixed_ecdh=66, // rfc4492 5.5.
    e_certificate_type_max=255
};

// rfc4492 (5.4)
enum ec_curve_type
{
    e_explicit_prime=1,
    e_explicit_char2=2,
    e_named_curve=3,
    e_ec_curve_max=255
};

typedef struct tls_handshake_t
{
    uint8_t  msg_type;
    uint8_t  length[3];
    uint8_t  msg[0];

}  tls_handshake_t;

// rfc 6347 sec 4.2.2.
typedef struct dtls_handshake_t
{
    uint8_t  msg_type;  // enum tls_handshake_type
    uint8_t  length[3]; // message length
    uint8_t  message_seq[2];
    uint8_t  fragment_offset[3];
    uint8_t  fragment_length[3];
    uint8_t  fragment_data[0];
    
}  dtls_handshake_t;

// rfc5246 (7.4.1.2.)
typedef struct tls_random_t
{
    uint32_t gmt_unix_time;
    uint8_t  random_bytes[28];

}  tls_random_t;

// rfc5246 (7.4.1.2.)
typedef struct tls_sessionid_t
{
    int     length;
    uint8_t id[32];

}  tls_sessionid_t;

// rfc5246 (7.4.1.4.)
// struct {
//   ExtensionType extension_type;
//   opaque extension_data<0..2^16-1>;
// } Extension;
//
// enum {
//   signature_algorithms(13), (65535)
// } ExtensionType;

// rfc5764 (4.1.1) use_srtp Extension
typedef struct use_srtp_t
{
    int      profiles_len; // in bytes; must be even numbers
    uint8_t *profiles_ptr; 

    int      srtp_mki_len; // 0 - 255
    uint8_t *srtp_mki_ptr;

}   use_srtp_t;

//
// struct ClientHello {
//   ProtocolVersion client_version;
//   Random random;
//   SessionID session_id;
//   opaque cookie<0..2^8-1>;   // DTLS
//   CipherSuite cipher_suites<2..2^16-2>;
//   CompressionMethod compression_methods<1..2^8-1>;
//   select (extensions_present) {
//     case false:
//       struct {};
//     case true:
//       Extension extensions<0..2^16-1>;
//   };
// } ClientHello;
//
typedef struct dtls_hello_t
{
    uint8_t   *version; // 2
    uint8_t   *random;  // sizeof(tls_random_t)
    int        session_id_len;
    uint8_t   *session_id_ptr;
    int        cookie_len;
    uint8_t   *cookie_ptr;
    int        cipher_suites_len;
    uint8_t   *cipher_suites_ptr;
    int        compression_methods_len;
    uint8_t   *compression_methods_ptr;
    int        extensions_len;
    uint8_t   *extentions_ptr;
    use_srtp_t use_srtp;
    // protocol data
    int        parsed_ok;
    int        size;
    uint8_t   *data;

}  dtls_hello_t;

// rfc rfc5246 7.4.1.4.
#define TYPE_SIGNATURE_ALGORITHMS  13
// rfc5764 section 9.
#define TYPE_USE_SRTP  14
// rfc7627 (5.1.)
#define TYPE_EXTENDED_MASTER_SCRETE 0x0017
// rfc5077 (3.2.)
#define TYPE_SESSION_TICKET_TLS 35

typedef struct tls_extension_t
{
    uint8_t   type[2];   // TYPE_USE_SRTP
    uint8_t   extension_size[2];
    uint8_t   extension_data[0];

}   tls_extension_t;

#define HOST_TO_BE2(b) BE2_TO_HOST(b)
#define BE2_TO_HOST(b) (((*((uint8_t*)(b)+0))<<8)|(*((uint8_t*)(b)+1)))

#define HOST_TO_BE3(b) BE3_TO_HOST(b)
#define BE3_TO_HOST(b) \
(((*((uint8_t*)(b)+0))<<16)|((*((uint8_t*)(b)+1))<<8)|(*((uint8_t*)(b)+2)))

#define HOST_TO_BE4(b) BE4_TO_HOST(b)
#define BE4_TO_HOST(b) \
((BE2_TO_HOST((uint8_t*)(b))<<16)|(BE2_TO_HOST((uint8_t*)(b)+2)))

#define HOST_TO_BE6(b) BE6_TO_HOST(b)
#define BE6_TO_HOST(b) \
((((uint64_t)(BE3_TO_HOST((uint8_t*)(b)+0)))<<24)|\
  ((uint64_t)(BE3_TO_HOST((uint8_t*)(b)+3))))

#define HOST_TO_BE8(b) BE8_TO_HOST(b)
#define BE8_TO_HOST(b) \
((((uint64_t)(BE4_TO_HOST((uint8_t*)(b)+0)))<<32)|\
  ((uint64_t)(BE4_TO_HOST((uint8_t*)(b)+4))))


#define V2_TO_BE(v,a) do{((uint8_t*)(a))[0]=(((v)>>8)&0xff);\
                         ((uint8_t*)(a))[1]=(((v)>>0)&0xff);}while(0)
#define V3_TO_BE(v,a) do{((uint8_t*)(a))[0]=(((v)>>16)&0xff);\
                         ((uint8_t*)(a))[1]=(((v)>>8)&0xff);\
                         ((uint8_t*)(a))[2]=(((v)>>0)&0xff);}while(0)
#define V4_TO_BE(v,a) do{V2_TO_BE(((v)>>16),a);\
                         V2_TO_BE((v),(uint8_t*)(a)+2);}while(0)

#endif // DTLS6347_H_

