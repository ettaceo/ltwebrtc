// file : sctp4960.h
// date : 05/07/2020
#ifndef SCTP4960_H_
#define SCTP4960_H_
#include <netinet/in.h>

// rfc4960 section 3.3.
enum
{
    e_type_data=0,
    e_type_init=1,
    e_type_init_ack=2,
    e_type_sack=3,
    e_type_heartbeat=4,
    e_type_heartbeat_ack=5,
    e_type_abort=6,
    e_type_shutdown=7,
    e_type_shutdown_ack=8,
    e_type_error=9,
    e_type_cookie_echo=10,
    e_type_cookie_ack=11,
    e_type_ecne=12,
    e_type_cwr=13,
    e_type_shutdown_complete=14,
    e_tyep_reconfigure=130,  // rfc6525 sec 3.
    e_type_forward_tsn=192,  // rfc3758 sec 3.2
    e_type_max=255
};

typedef struct stcpaddr
{
    short          sin_family;
    unsigned short sin_port;
    struct in_addr sin_addr;

}   stcpaddr_t;

typedef struct sctp_parameter_t
{
    unsigned short   type;
    unsigned short   length;
    unsigned char    value[0];

}   sctp_parameter_t;

typedef struct sctp_chunk_t
{
    unsigned char    type;
    unsigned char    flags;
    unsigned short   length;
    unsigned char    value[0];

}   sctp_chunk_t;

typedef struct sctp_common_t
{
    unsigned short source_port;
    unsigned short destination_port;
    unsigned int   verification_tag;
    unsigned int   checksum;
    sctp_chunk_t   chunk[0];

}   sctp_common_t;

#ifdef __cplusplus
extern "C" {
#endif

int   sctp_tx(void *tcb);

int   sctp_send_out(void *tcb, void *data, int size);

void *tcb_ice_session(void *tcb);

int   sctp_to_webrtc(void *tcb, char *text, int len);

int   sctp_send_close(void *tcb);

int   sctp_wait_writable(void *tcb, int timeout_ms);

int   sctp_send_reconfigure(void *tcb, int stream_number);

/*
int sctp_socket(void *parms);

int sctp_bind(int sock, stcpaddr_t *addr, void *parms);

int sctp_accept(int sock, stcpaddr_t *addr, void *parms);

int sctp_connect(int sock, stcpaddr_t *addr, void *parms);

int sctp_recv(int sock, void *buf, int len, void *parms);

int sctp_send(int sock, void *buf, int len, void *parms);

int sctp_close(int sock, int reason);

int sctp_ioctl(int sock, void *parms);
*/
#ifdef __cplusplus
}
#endif

#endif // SCTP4960_H_
