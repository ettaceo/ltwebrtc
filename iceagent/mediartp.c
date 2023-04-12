// file : mediartp.c was rtpmedia.c
// date : 04/25/2020
//
#define _GNU_SOURCE
#include <stdio.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>

#include "rfc_1889.h"
#include "srtp3711.h"
#include "mediartp.h"

#ifdef VIDEO_VIA_FILE
#include "qtplayer.h"
#include "tsplayer.h"
#endif

#define LOGI printf
//#define LOGV printf
#define LOGV(...)

#define RTCP_BIT_SR      (1<<0)
#define RTCP_BIT_RR      (1<<1)
#define RTCP_BIT_BYE     (1<<2)
#define RTCP_BIT_TMMB    (1<<3)
#define RTCP_BIT_FIR     (1<<4)

// copy from tsoutput.c
// 1500 - UDP_HDR(28) - RTP_HDR(12)
#define RTP_PACKET_MAX    1350 //1472
#define RTP_PAYLOAD_MAX   RTP_PACKET_MAX - 12

// ref. rfc5104 4.2.1 & 4.2.2
typedef struct fci_tmmb_t
{
    u32_t   ssrc;
    union
    {
        struct
        {
            u32_t   overhead:9;
            u32_t   mantissa:17;
            u32_t   exp:6;
        };

        u32_t u;  // used for changing endian
    };
}  fci_tmmb_t;

typedef struct
{
    unsigned char fmt:5;      // varies by packet type
    unsigned char p:1;        // padding flag
    unsigned char version:2;  // protocol version

    unsigned char pt;         // RTCP packet type

    u_int16 length;            // pkt len in words, w/o this word

    unsigned int packet_ssrc; // packet originator ssrc
    unsigned int media_ssrc;

    unsigned char fci[0];     // FCI variable length

}   rtcp_fb_t;

typedef struct rtpep_t
{
    const char *peer_addr;
    const char *self_addr;
    unsigned short peer_port;
    unsigned short self_port;
    unsigned int self_ssrc;
    unsigned int peer_ssrc;
    unsigned int nominal_kbps;
    unsigned int  rtp_ttl;// rtp ttl in milliseconds
    unsigned char pt;
    unsigned char alt_pt; // comfort noise payload type

    unsigned char crypto_suite;
    unsigned char key_length;
    unsigned char master_key[32];
    unsigned char master_salt[16]; // first 14-byte

    wchar_t suid[64];   // stream uuid

    // call to media source for actions
    void  *mctlx;
    void  (*mediactl)(void*, int);

}  rtpep_t;

// rtp endpoint
typedef struct rtppx_t
{
    int        sock;  // rtp/rtcp
    int        state;
    struct sockaddr_in  peer_addr;
    struct sockaddr_in  self_addr;

    unsigned char pt;     // payload type
    unsigned char alt_pt; // comfort noise, etc.
    // crypto
    unsigned char crypto_suite;
    unsigned char key_length;
    unsigned char master_key[32];
    unsigned char master_salt[16]; // first 14-byte

    unsigned int self_ssrc[1];  // in network order
    unsigned int peer_ssrc[1]; //

    rtp_hdr_t *rtp_hdr;
    u32_t      rtp_len;
    u32_t      o_stats;   // sent bytes count
    u32_t      p_stats;   // sent packets count

    u32_t      rtcp_len;
    u8_t      *rtcp_hdr;

    u8_t       rtp_buf[1500];  // for audio only
    u8_t       rtcp_buf[1500];
    u8_t       in_crypted[1500];
    u8_t       out_crypted[1500];

    u32_t      rtp_ttl;    // time-to-live in milliseconds
    u32_t      rtcp_tp;    // last time rtcp was processed
    u32_t      rtcp_cnt;   // rtcp sent count
    u32_t      rtcp_bits;  // rtcp compound
    u32_t      rtp_ts;     // rtp timestamp
    u32_t      rtp_ticks;  // corresponding system ticks
    u32_t      est_bw;     // estimated bandwidth
    fci_tmmb_t tmmbr;      // received tmmbr

    char      cname[64];   // ipv6 address up to 40 bytes

    wchar_t    suid[64];   // stream uuid, can be used as cname

    void     *crypx[2];    // crypto context for rtp, rtcp

    void     *upper;

    // back channel to media source process
    void     *mctlx;       // media control context
    void    (*mediactl)(void *mctl, int key);

}   rtppx_t;

//
// ring packet struct
//
typedef struct pkth_t
{
    u32_t  len:20;   // PKTMAXL

    u32_t  mid:12;   //  special if NULL_MESSAGE_ID

}  pkth_t;

// struct used for h264 rfc3984 refit
//
typedef struct refit_t
{
    pkth_t    pkth_;         // packet header
    u8_t      r3984[(1<<16)+4];  // rfc3984 output + rfc4571 header

    u8_t      meta_;         // sps, pps, delimiter,..
    u8_t      nalu_;         // first nalu
    u16_t     seq_;          // rtp packet sequence number
    u32_t     state;
    void    (*emit_)(void *, pkth_t*);
    void     *user_;         // user object passed to emit_()

}   refit_t;

//
typedef struct rtpvx_t
{
    long      rpos;

    rtppx_t   rtppx;

    refit_t   refit;   // h.264 refit per RFC3984

    // outbound rtp timestamp calculation
    s32_t     outts;   // outbound rtp timestamp
    s32_t     oldts;   // previous inbound rtp ts

    u64_t     vsutc;   // video stream utc time

}  rtpvx_t;

typedef struct rtpax_t
{
    rtppx_t   rtppx;

}   rtpax_t;

typedef struct rtpcx_t
{
    rtpvx_t   video;
    rtpax_t   audio;
#ifdef VIDEO_VIA_FILE
    void     *file_ctx; 
#endif

    void     *ice_sess;
    int     (*ice_emit)(void*,void*,int);
    void    (*rtp_quit)(void*);

    pthread_mutex_t  mutex;  // for ice_emit()

    pthread_t thread;

    int       quit;
    int       wait_idr;  // wait until next idr

}   rtpcx_t;

__attribute__((unused))
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

///////////////////////////////////////////////////////////////////////////////

// return system milliseconds tick count
static u32_t sys_ticks_ms(void)
{
    static u32_t off_sec;

    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    if( off_sec == 0 )
    {
        off_sec = tp.tv_sec;
    }

    return (tp.tv_sec - off_sec)*1000 + tp.tv_nsec/1000000;
}

///////////////////////////////////////////////////////////////////////////////
// copy from rtps_api.h
#define RFC4571_LEAD  4

#if (RFC4571_LEAD == 2)
#error "RFC4571_LEAD must be 4!"
    #define GET_RTP_LEN(p)         (((p)[0]<<8) + (p)[1])
    #define SET_RTP_LEN(p, l)      ((p)[0]=(u8_t)((l)>>8),(p)[1]=(u8_t)((l)&0xff))
#elif (RFC4571_LEAD == 4)
    #define GET_RTP_LEN(p)         (((p)[2]<<8) + (p)[3])
    #define SET_RTP_LEN(p, l)      ((p)[2]=(u8_t)((l)>>8),(p)[3]=(u8_t)((l)&0xff))
#else
    #error "Unknown RTP LEAD SIZE"
#endif


// offset to next startcode
static int off_to_start(unsigned char *pkt, int len)
{
    int j;
    for(j = 0; j <= len - 4; j++)
    {
        if( memcmp(pkt+j, "\x00\x00\x00\x01", 4) == 0 ) return j;
    }
    return len;  // -1
}

//
// generate an rfc3984 formatted packet from naively formatted rtp packet
//  with rfc 4571 header. results in mpexx->refit[]
//
int  h264_rfc3984(refit_t *refit, u8_t *trtp, int size)
{
    rtp_hdr_t *rtph;
    int        nalu;
    int        plen;
    int        poff;
    int        hoff;

    // kludge fix: @trtp has its leading 4-byte prefixed to regular
    //   rtp packets. it is not actually accessed here. rtp packets from 
    //   msdbuser do not include this 4-byte so we have to compensate for
    //   it. this is achieved by checking for rtp header version (2) at
    //   at the 2 high bits
    if( trtp[0] & 0x80 )
    {
        trtp -= 4;  // pretend a 4-byte lead
        size += 4;  // pretend a 4-byte lead
    }

    // RFC4571_LEAD must be 4
    plen = 2; // skip 2-byte channel number

    // clear rfc4571 header - 2-byte size
    memset(refit->r3984 + plen, 0, 2);
    plen += 2;
    // copy rtp header
    rtph = (void*)(refit->r3984 + plen);
    memcpy(rtph, trtp + plen, sizeof(rtp_hdr_t));
    plen += sizeof(rtp_hdr_t);
    if (rtph->x) // header extension - rfc1889(5.3.1)
    {
        plen += 4 + trtp[plen+2]*256 + trtp[plen+3];
    }
    poff = plen;  // offset to rtp payload

    hoff = poff + 4; // 4-byte start code

    // BUG: if a packet breaks off after start code, then @size == @hoff

    // for h.264 stream from raspberry pi, sps/pps/ are generated inline with
    // idr. as per rfc3984 we generate a STAP-A for sps/pps and a separate
    // packet (likely FU) for idr. SPS type is 0x07
    if( size > hoff + 1 &&
        0 == memcmp(trtp + poff, "\x00\x00\x00\x01", 4) &&
        (trtp[hoff] & 0x1f)==0x07 )
    {
        int k;
        int pend = size - poff;
        // search for next startcode
        if( (k = off_to_start(trtp + poff + 4, pend - 4)) > 0 )
        {
            unsigned char *pkt_ = refit->r3984;

            int qoff = plen; // start of rtp payoad
            // place STAP-A type
            pkt_[qoff+0] = (trtp[hoff]&0xe0)|24;
            pkt_[qoff+1] = k/256; // high
            pkt_[qoff+2] = k%256;
            memcpy(pkt_+qoff+3, trtp + poff + 4, k);
            qoff += (3+k);
            poff += (4+k); // location of PPS startcode
            pend -= (4+k);
            if( (k = off_to_start(trtp + poff + 4, pend - 4)) > 0 )
            {
                pkt_[qoff+0] = k/256;
                pkt_[qoff+1] = k%256;
                memcpy(pkt_+qoff+2, trtp + poff + 4, k);
                qoff += (2+k);
                poff += (4+k); // location of IDR startcode
                pend -= (4+k);
            }
            // dispatch
            refit->state = 1;  //signal idr
            SET_RTP_LEN(refit->r3984, qoff - RFC4571_LEAD);
            refit->pkth_.len = qoff;
            rtph->seq = htons(++refit->seq_);
            // clear marker
            char marker = rtph->m;
            rtph->m = 0;
            unsigned int ts = rtph->ts;
            // send sps/pps as a separate rtp packet
            if( refit->emit_ ) refit->emit_(refit->user_, &refit->pkth_);
            // recover seq and timestamp - overwriten by refit->emit_
            rtph->seq = htons(refit->seq_);
            rtph->ts = ts;
            // set marker for idr
            rtph->m = marker;
            hoff = poff + 4; // 4-byte start code
        }
    }

    // payload with start code
    if( size > hoff && 0 == memcmp(trtp + poff, "\x00\x00\x00\x01", 4) )
    {
        refit->meta_ = nalu = (trtp[hoff] & 0x1f); // save as meta_

        // check for single/special NAL unit packet
        // 6-SEI 7-SPS 8-PPS 9-delimiter
        // we may have to check payload size. VLC doesn't like SEI
        // been preceded by FU indicator
        // [02/28/2016] rpivideo has sps/pps in front of idr
        if(rtph->m || nalu == 6 /*|| nalu == 7 || nalu == 8 || nalu == 9*/)
        {
            // no need for FU header indicator. copy payload less startcode
            memcpy(refit->r3984 + plen, trtp + hoff, size - hoff);
            plen += (size - hoff);
        }
        else if( size > hoff + 1 ) // at least 2 bytes after start code
        {
            refit->nalu_ = trtp[hoff];  // needed for FU header indicators
            // add FU header indicator - NRI from nalu and type 28
            refit->r3984[plen++] = (refit->nalu_ & 0x60) | 28;
            // add FU header - nalu + SER bits with start bit set
            refit->r3984[plen++] = 0x80 | nalu;
            // packet payload less startcode and nalu byte
            memcpy(refit->r3984 + plen, trtp + hoff + 1, size - (hoff + 1));
            plen += (size - (hoff + 1));
        }
        else assert(0); // invalid
    }
    else // payload without startcode
    {
        refit->meta_ = 0;
        nalu = (refit->nalu_ & 0x1f);
        if( rtph->m ) nalu |= 0x40;  // set end bit in SER bits

        // add FU header indicator - NRI from nalu and type 28
        refit->r3984[plen++] = (refit->nalu_ & 0x60) | 28;
        // add FU header - nalu + SER bits with start bit set
        refit->r3984[plen++] = nalu;
        // packet payload less startcode and nalu byte
        if( size > poff )
        {
            memcpy(refit->r3984 + plen, trtp + poff, size - poff);
        }
        plen += (size - poff);
    }

    if( refit->meta_ == 5 ) refit->state = 1;  // signal idr

    // set rfc4571 size
    SET_RTP_LEN(refit->r3984, plen - RFC4571_LEAD);

    // set length
    refit->pkth_.len = plen;

    if( refit->state > 0 && refit->emit_ )
    {
        rtph->seq = htons(++refit->seq_);
        refit->emit_(refit->user_, &refit->pkth_);
    }

    return plen;
}

static int is_start_idr(unsigned char *data)
{
    unsigned char type = (data[0] & 0x1f);
    // if STAP-A check next byte SPS type 7
    if( type == 24 ) type = (data[3] & 0x1f);
    // if FU-A, check next byte IDR type 5
    //if( type == 28 ) type = (data[1] & 0x1f);
    return (type==7 /*|| type == 5*/);
}

#ifdef APPLE_HOMEKIT_SILENCE

unsigned char aac_silent[]=
{
   0x98, 0x60, 0x31, 0xa7, 0xa0, 0xfb, 0x1f, 0x00, 0x01, 0x18,
   0xe1, 0x5f, 0x80, 0x08, 0xec, 0x00, 0xbc, 0x10, 0x00, 0x00,
   0x02, 0x14, 0xb4, 0xb4, 0xb4, 0xb4, 0xb4, 0xb4, 0xb4, 0xb4,
   0xb4, 0xb4, 0xb4, 0xb4, 0xb4, 0xb4, 0xb4, 0xb4, 0xb4, 0xb4,
   0xb4, 0xb4, 0xb4, 0xb4, 0xb4, 0xb4, 0xb4, 0xb4, 0xb4, 0xb4,
   0xb4, 0xb4, 0xb4, 0xb4, 0xb4, 0xb4, 0xb4, 0xb4, 0xb4, 0xb4,
   0xb4, 0xb4, 0xb4, 0xb4, 0xb4, 0xb4, 0xb4, 0xb4, 0xb4, 0xb4,
   0xb4, 0xb4, 0xb4, 0xb4, 0xb4, 0xb4, 0xb4, 0xb4, 0xb4, 0xb4,
   0xb4, 0xb4, 0xb4, 0xb4, 0xb4, 0xb4, 0xb4, 0xb4, 0xb4, 0xa0
};

static int check_audio_sync(rtpcx_t *cx, rtppx_t *ap, rtppx_t *vp)
{
    int e;
    unsigned short *wd;

    ap->rtp_hdr->ts = vp->rtp_hdr->ts;
    ap->rtp_hdr->seq = htons(ntohs(ap->rtp_hdr->seq)+1);
    wd = (void*)(ap->rtp_hdr + 1);
#ifdef USE_AAC_SILENCE
    ap->rtp_hdr->pt = ap->pt;
    wd[0] = htons(16);            // au-header width in bits
    wd[1] = sizeof(aac_silent);
    wd[1] <<= 3;
    wd[1] = htons(wd[1]);
    memcpy(wd+1, aac_silent, sizeof(aac_silent));
    if( ap->crypx[0] == 0 )
    {
        e = 12+4+sizeof(aac_silent);

        if( ap->sock != -1 )
        {
            send(ap->sock, ap->rtp_hdr, e, MSG_NOSIGNAL);
        }
        else if( cx->ice_emit )
        {
            cx->ice_emit(cx->ice_sess, (uint8_t*)ap->rtp_hdr, e);
        }
    }
    else
    {
        e = encrypt_rtp_128(ap->crypx[0], (void*)ap->rtp_hdr, 12+4+sizeof(aac_silent), ap->crypted);

        if( ap->sock != -1 )
        {
            e = send(ap->sock, ap->crypted, e, MSG_NOSIGNAL);
        }
        else if( cx->ice_emit )
        {
            cx->ice_emit(cx->ice_sess, ap->crypted, e);
        }
    }
#else
    // may slow down to every 1 second
    ap->rtp_hdr->pt = ap->alt_pt;
    wd[0] = 0;
    if( ap->crypx[0] == 0 )
    {
        e = 13;

        if( ap->sock != -1 )
        {
            send(ap->sock, ap->rtp_hdr, e, MSG_NOSIGNAL);
        }
        else if( cx->ice_emit )
        {
            cx->ice_emit(cx->ice_sess, (uint8_t*)ap->rtp_hdr, e);
        }
    }
    else
    {
        e = encrypt_rtp_128(ap->crypx[0], (void*)ap->rtp_hdr, 13, ap->crypted);

        if( ap->sock != -1 )
        {
            e = send(ap->sock, ap->crypted, e, MSG_NOSIGNAL);
        }
        else if( cx->ice_emit )
        {
            cx->ice_emit(cx->ice_sess, ap->crypted, e);
        }
    }
#endif
    if( e > 0 )
    {
        ap->o_stats += e;
        ap->p_stats += 1;
    }
    return e;
}
#endif // APPLE_HOMEKIT_SILENCE

static void rtp_video_send(void *user, pkth_t  *msg)
{
    rtpcx_t *cx = user;
    rtppx_t *vp = &cx->video.rtppx;
    char    *pkt;
    int      e=0;

    pkt = (char*)(msg+1);
    vp->rtp_hdr = (void*)(pkt+4);
    vp->rtp_len = msg->len - 4;

    if(vp->rtp_len <= 0) return;

    int id_idr = is_start_idr((void*) (vp->rtp_hdr + 1));
    vp->rtp_hdr->ssrc = vp->self_ssrc[0];
    vp->rtp_hdr->pt = (unsigned char) vp->pt;

    if( vp->state > 1 || id_idr )
    {
        if( vp->crypx[0] == 0 )
        {
            e = vp->rtp_len;

            if( vp->sock != -1 )
            {
                send(vp->sock, vp->rtp_hdr, vp->rtp_len, MSG_NOSIGNAL);
            }
            else if( cx->ice_emit )
            {
                cx->ice_emit(cx->ice_sess, (uint8_t*)vp->rtp_hdr, vp->rtp_len);
            }
        }
        else
        {
            // ref. rtp_audio_send()
            pthread_mutex_lock(&cx->mutex);

            e = encrypt_rtp_128(vp->crypx[0], (void*)vp->rtp_hdr, vp->rtp_len, vp->out_crypted);

            if( vp->sock != -1 )
            {
                e = send(vp->sock, vp->out_crypted, e, MSG_NOSIGNAL);
            }
            else if( cx->ice_emit )
            {
                cx->ice_emit(cx->ice_sess, vp->out_crypted, e);
            }

            pthread_mutex_unlock(&cx->mutex);
        }
    }
    if( e != vp->rtp_len ) {}

    // send comfort noise
    if( id_idr )
    {
        // keep mapping between ntp and rtp ts
        vp->rtp_ts = ntohl(vp->rtp_hdr->ts);
        vp->rtp_ticks = sys_ticks_ms();
#ifdef APPLE_HOMEKIT_SILENCE
        check_audio_sync(cx, &(cx->audio.rtppx), vp);
#endif
    }

    if( e > 0 )
    {
        vp->o_stats += vp->rtp_len;
        vp->p_stats += 1;
    }
}

#define MAXTS_DELTA 90000   // 1 seconds in 90KHz

// @ext to be 12 bytes : 'ut' 2 lo_32 hi_32
static u64_t rtp_ext_utc(u8_t *ext)
{
    u64_t utc = 0;
    if( ext[0] == 'u' && ext[1] == 't' )
    {
        int i;
        // hi 4 bytes in big-endian
        for(i=8; i < 12; i++) utc = (utc<<8) + (u64_t)(ext[i]);
        // lo 4 bytes in big-endian
        for(i=4; i < 8; i++) utc = (utc<<8) + (u64_t)(ext[i]);
    }

    return utc;
}

static int annex_b_idr(u8_t *ptr, int len)
{
    if( len < 5 ) return 0;
    if( 0 != memcmp(ptr, "\x00\x00\x00\x01", 4) ) return 0;
    return (ptr[4]&0x1f)==7; // type SPS
}

// called once per inbound jumbo rtp packet
static void * rtp_packet_fixup(rtpvx_t *vx, void *pkt, int *len)
{
    rtp_hdr_t *rtph = pkt;
    // firefox cannot handle rtp header extension - remove it
    if( rtph->x )
    {
        u8_t *ext = (void*)(rtph+1);
        // call rtp_ext_utc() before moving rtp header
        vx->vsutc = rtp_ext_utc(ext);
        int gap = 4 *(1+ext[2]*256+ext[3]);
        *len -= gap;
        // move @rtph to skip extension
        rtph = (void*)((char*)pkt + gap);
        memmove(rtph, pkt, sizeof(rtp_hdr_t));
        rtph->x = 0;
    }
    // maintain timestamp continuity - maximum gap at 1 second
    s32_t newts = ntohl(rtph->ts);
    s32_t delta = newts - vx->oldts;
    if( delta < 0 || delta > MAXTS_DELTA)
    {
        delta = MAXTS_DELTA;
    }
    vx->outts += delta;
    // put outbound rtp ts
    rtph->ts = htonl(vx->outts);
    // update old ts
    vx->oldts = newts;

    return rtph;  // new rtp header position
}

// defined in iceagent.c
extern int webrtc_send_utc(void *ice_sess, uint64_t utc);

#define MAX_RTP_LENGTH  1400

static int rtp_pump(void *cx, void *pkt, int len)
{
    rtpvx_t *vx = &((rtpcx_t*)cx)->video;
    rtppx_t *vp = &vx->rtppx;
    // @pkt and @len null to notify quiting
    if( vp->state && pkt && len > 0 )
    {
        pkt = rtp_packet_fixup(vx, pkt, &len);
        int   size;
        int   pnt;
        rtp_hdr_t *rtph = pkt;
        // assuming h264 stream with start code 0001
        // send video utc per idr if utc is not ~0LL - this is to prevent
        // from sending the same utc repeatedly
        if( annex_b_idr((void*)(rtph+1), len) && vx->vsutc != ~0LL)
        {
            // it is possible sctp data channel not yet ready
            if( webrtc_send_utc(((rtpcx_t*)cx)->ice_sess, vx->vsutc) )
            {
                vx->vsutc = ~0LL;
            }
        }

        int   m = rtph->m;
        // fragment jumbo rtp packet into packets of upto MAX_RTP_LENGTH
        for(size = len, pnt = sizeof(rtp_hdr_t); pnt < len;)
        {
            if( pnt > sizeof(rtp_hdr_t) /*0*/ )
            {
                rtph = (void*)((char*)pkt + pnt - sizeof(rtp_hdr_t));
                memmove(rtph, pkt, sizeof(rtp_hdr_t));
                rtph->seq = 0; // h264_rfc3984() resets sequence number
                size = sizeof(rtp_hdr_t) + len - pnt;
            }
            if( size > MAX_RTP_LENGTH ) size = MAX_RTP_LENGTH;
            rtph->m = ((m!=0) && (len - (pnt - sizeof(rtp_hdr_t)) <= MAX_RTP_LENGTH)) ? 1 : 0;

            // refit to rfc3984 -check max length!
            h264_rfc3984(&vx->refit, (void*)rtph, size);
            // move @pnt to next packet payload
            pnt += (pnt==0? size : size - sizeof(rtp_hdr_t));
        }
    }
    return len;
}

static void tp2ntp(struct timespec *tp, uint32_t ntp[2])
{
    uint64_t *aux = (void*)ntp;

    *aux = tp->tv_nsec;
    *aux <<= 32;
    *aux /= 1000000000LL;

    ntp[1] = htonl(ntp[0]);

    ntp[0] = tp->tv_sec;
    ntp[0] += 2208988800UL;   // offset in seconds to 1900 from 1970

    ntp[0] = htonl(ntp[0]);

} /* tp2ntp */


static void rtcp_set_ntp_ts(rtppx_t *px, rtcp_sr_info_t *sr)
{
    struct timespec tp={0,0};
    int    ut = 0;

    clock_gettime(CLOCK_REALTIME, &tp);

    tp2ntp(&tp, (void*)&sr->ntp_sec);

    // ntp to rtp timestamp mapping
    if( px->rtp_ticks )
    {
        // previous rtp_ts add delta in 90KHz ticks
        ut = (int)px->rtp_ts + ((int)sys_ticks_ms() - (int)px->rtp_ticks) * 90;
    }

    sr->rtp_ts = htonl(ut);
}

// prepare a rtcp sr to send
// this is the first rtp packet in a compound
//
static void rtcp_make_sr(rtppx_t *px)
{
    rtcp_common_t *hdr;

    hdr = (void*)((char*)px->rtcp_hdr + px->rtcp_len);

    memset(hdr, 0, sizeof(*hdr));
    // common header
    hdr->version = 2;
    hdr->count   = 0;    // no reception report
    hdr->pt      = 200;  // sender report

    rtcp_sr_info_t *sr = (void*)(hdr + 1);

    sr->ssrc    = px->self_ssrc[0];
    hdr->length += 1;

    if( px->p_stats == 0 && px->o_stats == 0 )
    {
        // rfc3550 6.4.2 final paragraph
        hdr->pt = 201; // change to empty RR
    }
    else
    {
        rtcp_set_ntp_ts(px, sr);
        sr->psent = htonl(px->p_stats);
        sr->osent = htonl(px->o_stats);
        hdr->length += 5; // sizeof rtcp_sr_info_t less ssrc
    }
    // rtcp packet length so far = sizeof rtcp_common_t + sr length
    px->rtcp_len += (4 + hdr->length * 4);

    // keep this final line
    hdr->length = htons(hdr->length);
}

//
// this is called after calling rtcp_make_sr() or rtcp_make_rr()
// second rtp packet in compound
//
static void rtcp_make_sdes(rtppx_t *px)
{
    rtcp_common_t *hdr;

    hdr = (void*)((char*)px->rtcp_hdr + px->rtcp_len);

    memset(hdr, 0, sizeof(*hdr));
    // common header
    hdr->version = 2;
    hdr->count   = 1;
    hdr->pt      = 202;  // SDES

    struct rtcp_sdes *sdes = (void*)(hdr+1);

    sdes->src = px->self_ssrc[0];
    hdr->length += 1;

    sdes->item[0].type = 1; // cname
    sdes->item[0].length = strlen(px->cname);

    int wlen = ((2 + sdes->item[0].length + 3) / 4);

    // zero-out all bytes of data
    memset(sdes->item[0].data, 0, wlen * 4 - 2);

    hdr->length += wlen;

    memcpy(sdes->item[0].data, px->cname, sdes->item[0].length);

    px->rtcp_len += (4 + hdr->length * 4);

    // keep this final line
    hdr->length = htons(hdr->length);
}

#if 0
static void rtcp_make_bye(rtppx_t *px)
{
    rtcp_common_t *hdr;
    LOGV("[%s:%u] enter px->rtcp_len=%d\n", __func__, __LINE__, px->rtcp_len);

    hdr = (void*)((char*)px->rtcp_hdr + px->rtcp_len);

    memset(hdr, 0, sizeof(*hdr));
    // common header
    hdr->version = 2;
    hdr->count   = 1;
    hdr->pt      = 203;  // bye

    u32_t *src = (void*)(hdr+1);

    src[0] = px->self_ssrc[0];
    hdr->length += 1;

    px->rtcp_len += (4 + hdr->length * 4);

    // keep this final line
    hdr->length = htons(hdr->length);
}
#endif

// rfc5104 4.2.2
static void rtcp_make_tmmbn(rtppx_t *px)
{
    rtcp_fb_t  *fb;
    fci_tmmb_t *tmmb;

    fb = (void*)((char*)px->rtcp_hdr + px->rtcp_len);

    memset(fb, 0, sizeof(*fb));
    // common header
    fb->version = 2;
    fb->fmt     = 4;    // TMMBN
    fb->pt      = 205;  // RTPFB
    fb->packet_ssrc = px->self_ssrc[0];
    fb->media_ssrc = 0; // rfc5104 4.2.2.2 paragraph 2

    tmmb = (void*)fb->fci;

    tmmb->ssrc = px->peer_ssrc[0]; // rfc5104 4.2.2.1 owner
    tmmb->u = ntohl(px->tmmbr.u);

    tmmb->u = htonl(tmmb->u);

    fb->length = 4;

    px->rtcp_len += (4 + fb->length * 4);

    // keep this final line
    fb->length = htons(fb->length);
}

static void  rtpfb_handler(rtcp_fb_t *fb, rtppx_t *px)
{
    switch(fb->fmt)
    {
    case 1:  // rfc4585 6.2: Generic NACK
        break;
    case 3:  // rfc5104 4.2: Temporary Maximum Media Stream Bit Rate Request (TMMBR)
        px->tmmbr = *(fci_tmmb_t*)(void*)(fb->fci);
        px->rtcp_bits |= RTCP_BIT_TMMB;
        break;
    case 4:  // rfc5104 4.2: Temporary Maximum Media Stream Bit Rate Notification (TMMBN)
        break;
    default:
        LOGV("[%s:%u] ? received fb->fmt(%d)\n", __func__, __LINE__, fb->fmt);
        break;
    }
}

static void  psfb_handler(rtcp_fb_t *fb, rtppx_t *px)
{
    switch(fb->fmt)
    {
    case 1:  // rfc4585 6.3: Picture Loss Indication (PLI)
        break;
    case 2:  // rfc4585 6.3: Slice Loss Indication (SLI)
        break;
    case 3:  // rfc4585 6.3: Reference Picture Selection Indication (RPSI)
        break;
    case 4:  // rfc5104 4.3: Full Intra Request (FIR) Command
        px->rtcp_bits |= RTCP_BIT_FIR;
        if( px->upper) ((rtpvx_t*)px->upper)->rpos = -1; // [11/18/2018]
        break;
    case 5:  // rfc5104 4.3: Temporal-Spatial Trade-off Request (TSTR)
        break;
    case 6:  // rfc5104 4.3: Temporal-Spatial Trade-off Notification (TSTN)
        break;
    case 7:  // rfc5104 4.3: Video Back Channel Message (VBCM)
        break;
    case 15: // rfc4585 6.4: Application layer FB (AFB) message
        break;
    default:
        LOGV("[%s:%u] received fb->fmt(%d)\n", __func__, __LINE__, fb->fmt);
        break;
    }
}

static void  rtcp_handler(rtpcx_t *cx, rtppx_t *px)
{
    rtcp_t  *rtcp;
    int     rlen=0;

    if( px->crypx[1] == 0 )
    {
        if( px->rtcp_len > 0 )
        {
            rlen = px->rtcp_len;
        }
        else if( px->sock != -1 )
        {
            rlen = recv(px->sock, px->rtcp_buf, sizeof(px->rtcp_buf), MSG_DONTWAIT);
        }

        if( rlen <= 0 ) return;
        if( rlen < 4 ) return;

        // RFC5761 single port rtp/rtcp
        if( ((rtp_hdr_t*)px->rtcp_buf)->pt < 64 ||
            ((rtp_hdr_t*)px->rtcp_buf)->pt > 95 )
        {
            // ignore rtp packets
            return;
        }
    }
    else
    {
        if( px->rtcp_len > 0 )
        {
            rlen = px->rtcp_len;
        }
        else if( px->sock != -1 )
        {
            rlen = recv(px->sock, px->in_crypted, sizeof(px->in_crypted), MSG_DONTWAIT);
        }

        if( rlen <= 0 ) return;
        if( rlen < 4 ) return;

        // RFC5761 single port rtp/rtcp
        if( ((rtp_hdr_t*)px->in_crypted)->pt < 64 ||
            ((rtp_hdr_t*)px->in_crypted)->pt > 95 )
        {
            // ignore rtp packets
            return;
        }

        rlen = decrypt_rtcp_128(px->crypx[1], px->in_crypted, rlen, px->rtcp_buf);
    }

    // NOTE:  ap->rtcp_hdr = ap->rtcp_buf;

    px->rtcp_bits = 0;  // clear all flags

    for(rtcp = (void*)px->rtcp_hdr; (char*)rtcp < (char*)px->rtcp_hdr + rlen;)
    {
        switch( rtcp->common.pt )
        {
        case 200: // rfc3550: sender report
            break;
        case 201: // rfc3550: receiver report
            break;
        case 202: // rfc3550: SDES
            break;
        case 203: // rfc3550: bye
            px->state = 0; // stop sending
            break;
        case 205: // rfc4585: Transport layer FB message
            rtpfb_handler((rtcp_fb_t*)rtcp, px);
            break;
        case 206: // rfc4585: Payload-specific FB message
            psfb_handler((rtcp_fb_t*)rtcp, px);
            break;
        default:
            break;
        }
        // move to next
        rtcp = (void*)((char*)rtcp + (ntohs(rtcp->common.length) + 1) * 4);
    }
    if( px->rtcp_bits & RTCP_BIT_BYE ) return;
    if( px->rtcp_bits & RTCP_BIT_FIR ) return;

    // format rtcp message
    px->rtcp_len = 0;
    rtcp_make_sr(px);
    rtcp_make_sdes(px);
    if( px->rtcp_bits & RTCP_BIT_TMMB )
    {
        rtcp_make_tmmbn(px);
    }

    u32_t ticks =  sys_ticks_ms();

    // minimal 0.5 second between rtcp sends
    //if( (int)ticks - (int)px->rtcp_tp > 500 )
    {
        // send
        if( px->crypx[1] == 0 )
        {
            if( px->sock != -1 )
            {
                rlen = send(px->sock, px->rtcp_hdr, px->rtcp_len, MSG_NOSIGNAL);
            }
            else if( cx->ice_emit )
            {
                cx->ice_emit(cx->ice_sess, px->rtcp_hdr, px->rtcp_len);
            }
        }
        else
        {
            rlen = encrypt_rtcp_128(px->crypx[0], px->rtcp_hdr, px->rtcp_len, px->in_crypted);

            if( px->sock != -1 )
            {
                rlen = send(px->sock, px->in_crypted, rlen, MSG_NOSIGNAL);
            }
            else if( cx->ice_emit )
            {
                rlen = cx->ice_emit(cx->ice_sess, px->in_crypted, rlen);
            }
        }

        // send done
        px->rtcp_len = 0;

        if( rlen < 0 ) {}
        else px->rtcp_cnt += 1;

        px->rtcp_tp = ticks;
    }
    if( px->rtcp_bits & RTCP_BIT_TMMB )
    {
        fci_tmmb_t tmmb = px->tmmbr;

        tmmb.u = ntohl(tmmb.u);

        if( tmmb.exp == 0 && tmmb.mantissa == 0 )
        {
            px->state = 1;
        }
        else px->state = 2;
    }
}

// return 1 if expired
static int  rtcp_checker(rtppx_t *px)
{
    if( px->rtp_ttl > 0 && px->rtcp_tp > 0)
    {
        u32_t ticks = sys_ticks_ms();
        // add 500ms to ttl for stability
        if( (int)ticks - (int)px->rtcp_tp > px->rtp_ttl + 500 )
        {
            LOGV("[%s:%u] ttl expired( ticks=%u rtcp_tp=%u rtp_ttl=%d\n",
                __func__, __LINE__, ticks, px->rtcp_tp, px->rtp_ttl);

            return 1;
        }
    }

    return 0;
}

static void  * rtp_joint_thread(void *cx)
{
    rtpvx_t *vx = &((rtpcx_t *)cx)->video;
    rtppx_t *vp = &(vx->rtppx);
    rtpax_t *ax = &((rtpcx_t *)cx)->audio;
    rtppx_t *ap = &(ax->rtppx);
    int     e=0;
    int     ss=0;

    ap->sock = -1;

    if( ap->peer_addr.sin_port )
    {
        ap->sock = socket(AF_INET, SOCK_DGRAM, 0);

        e = bind(ap->sock, (struct sockaddr*)&ap->self_addr, sizeof(ap->self_addr));
        if( e ) {}

        e = connect(ap->sock, (struct sockaddr*)&ap->peer_addr, sizeof(ap->peer_addr));
        if( e ) {}
    }

    if( ss <= ap->sock ) ss = ap->sock + 1;

    // initialize rtp header
    ap->rtp_hdr = (void*)ap->rtp_buf;
    ap->rtp_hdr->version = 2;
    ap->rtp_hdr->pt = ap->pt;
    ap->rtp_hdr->ssrc = ap->self_ssrc[0];

    ap->rtcp_hdr = ap->rtcp_buf;

    // initialize srtp
    if( ap->key_length > 0 )
    {
        ap->crypx[1] =
        ap->crypx[0] = init_srtp_crypt(ap->master_key, ap->key_length, ap->master_salt);
        LOGV("[%s:%u] audio crypx=%p\n", __func__, __LINE__, ap->crypx[0]);
    }

    // initialize rtcp tick count
    if( ap->rtp_ttl > 0 ) ap->rtcp_tp = sys_ticks_ms();

    vp->sock = -1;

    if( vp->peer_addr.sin_port )
    {
        vp->sock = socket(AF_INET, SOCK_DGRAM, 0);

        e = bind(vp->sock, (struct sockaddr*)&vp->self_addr, sizeof(vp->self_addr));
        if( e ) {}

        e = connect(vp->sock, (struct sockaddr*)&vp->peer_addr, sizeof(vp->peer_addr));
        if( e ) {}
    }

    if( ss <= vp->sock ) ss = vp->sock + 1;

    vp->rtcp_hdr = vp->rtcp_buf;

    // initialize rtcp tick count
    if( vp->rtp_ttl > 0 ) vp->rtcp_tp = sys_ticks_ms();

    vp->upper = vx;
    vx->refit.user_ = cx;
    vx->refit.emit_ = rtp_video_send;

    // initialize srtp
    if( vp->key_length > 0 )
    {
        vp->crypx[1] =
        vp->crypx[0] = init_srtp_crypt(vp->master_key, vp->key_length, vp->master_salt);
        LOGV("[%s:%u] video crypx=%p\n", __func__, __LINE__, vp->crypx[0]);
    }

    int poll_wait = 100;  // milliseconds

    while( ! ((rtpcx_t *)cx)->quit )
    {
        struct pollfd fds[2]={{vp->sock, POLLIN, 0}, {ap->sock, POLLIN, 0}};

        e = poll(fds, sizeof(fds)/sizeof(fds[0]), poll_wait);  // 

        if( e < 0 && errno == EINTR ) continue;

        if( e > 0 )
        {
            if( (fds[0].revents & POLLIN) ) rtcp_handler(cx, vp);
            if( (fds[1].revents & POLLIN) ) rtcp_handler(cx, ap);
        }

        // check rtcp activity - don't change (((rtpcx_t *)cx)->quit
        if( vp->sock != -1 && rtcp_checker(vp) ) break;
    }

    if( vp->sock != -1 ) close(vp->sock);
    vp->sock = -1;

    if( ap->sock != -1 ) close(ap->sock);
    ap->sock = -1;

    // free cryptos if they are alloacted locally
    if( vp->crypx[0] == vp->crypx[1] ) free_srtp_crypt(vp->crypx[0]);
    vp->crypx[0] = vp->crypx[1] = 0;
    if( ap->crypx[0] == ap->crypx[1] ) free_srtp_crypt(ap->crypx[0]);
    ap->crypx[0] = ap->crypx[1] = 0;
    LOGV("[%s:%u] exit rtp session e=%d\n", __func__, __LINE__, e);

    if( ((rtpcx_t *)cx)->rtp_quit )
    {
        ((rtpcx_t *)cx)->rtp_quit(((rtpcx_t *)cx)->ice_sess);
    }

    return 0;
}

static void  rtp_set_end_pts(rtppx_t *px, rtpep_t *ep)
{
    px->peer_addr.sin_family = AF_INET;
    if( ep->peer_addr ) px->peer_addr.sin_addr.s_addr = inet_addr(ep->peer_addr);
    px->peer_addr.sin_port = htons(ep->peer_port);

    px->self_addr.sin_family = AF_INET;
    if( ep->self_addr ) px->self_addr.sin_addr.s_addr = inet_addr(ep->self_addr);
    px->self_addr.sin_port = htons(ep->self_port);

    px->self_ssrc[0] = htonl(ep->self_ssrc);
    px->peer_ssrc[0] = htonl(ep->peer_ssrc);
    px->pt = ep->pt;
    px->alt_pt = ep->alt_pt;

    px->crypto_suite = ep->crypto_suite;
    px->key_length = ep->key_length;
    memcpy(px->master_key, ep->master_key, sizeof(px->master_key));
    memcpy(px->master_salt, ep->master_salt, sizeof(px->master_salt));
/*
    {
        int j;
        unsigned char *ptr = px->master_key;
        LOGV("[%s:%u] (%s)px->key_length=%d\n", __func__, __LINE__,
            px->alt_pt==0?"Video":"Audio", px->key_length);
        for(j=0; j< (int)px->key_length; j++)LOGV("%.2X", ptr[j]);
        LOGV("\n");
        ptr=px->master_salt;
        for(j=0; j< 14; j++)LOGV("%.2X", ptr[j]);
        LOGV("\n");
    }
*/
    px->est_bw = ep->nominal_kbps * 1000;

    // rtp_ttl is the interval for which rtcp not heard of to terminate rtp
    px->rtp_ttl = ep->rtp_ttl;

    // copy suid
    memcpy(px->suid, ep->suid, sizeof(ep->suid));

    // media control callback
    px->mctlx = ep->mctlx;
    px->mediactl = ep->mediactl;

}

static void  * rtp_joint_setup(rtpep_t *video, rtpep_t *audio)
{
    rtpcx_t *rtpcx = calloc(1, sizeof(rtpcx_t));

    if( rtpcx == 0 ) return 0;

    if( audio )
    {
        rtp_set_end_pts(&rtpcx->audio.rtppx, audio);

        sprintf(rtpcx->audio.rtppx.cname, "audio@%s", audio->self_addr);
    }

    if( video )
    {
        rtp_set_end_pts(&rtpcx->video.rtppx, video);

        sprintf(rtpcx->video.rtppx.cname, "video@%s", video->self_addr);
    }

    pthread_mutex_init(&rtpcx->mutex, 0);

    int e = pthread_create(&rtpcx->thread, 0, rtp_joint_thread, rtpcx);
    (void)e;

    return rtpcx;
}

static void   rtp_joint_reset(void *cx)
{
    rtpcx_t *rtpcx = cx;

    rtpcx->quit = 1;

    int e = pthread_join(rtpcx->thread, 0);
    if(e){}

    pthread_mutex_destroy(&rtpcx->mutex);

    LOGV("[%s:%u] free(rtpcx=%p) audio p_state=%u\n",
        __func__, __LINE__, rtpcx, rtpcx->audio.rtppx.p_stats);
    free(rtpcx);
}

static void set_video_state(void *cx, int state)
{
    rtpcx_t *rtpcx = cx;

    rtpcx->video.rtppx.state = state;
}

extern void * get_srtp_cryptos(void *sess);
extern void * ice_session_peer(void *sess);
extern char * get_media_path();

#define RTP_TIMEOUT  7490

// rtcp timeout in RTP_TIMEOUT milliseconds
void * rtp_media_setup(void *sess, int(*emit)(void*,void*,int),
                       void(*quit)(void*))
{
    rtpcx_t *rtpcx;
    rtpep_t  video={.peer_addr=0, .self_addr=0, .rtp_ttl=RTP_TIMEOUT,
                    .peer_port=0, .self_port=0, .self_ssrc=RTP_SSRC_BE,
                    .pt=RTP_H264_VIDEO_PT};
    rtpep_t  audio={.peer_addr=0, .self_addr=0,
                    .peer_port=0, .self_port=0, .self_ssrc=RTP_SSRC_BE,
                    .pt=RTP_CONFOR_NOISE_PT};

    rtpcx = rtp_joint_setup(&video, &audio);

    rtpcx->ice_sess = sess;
    rtpcx->ice_emit = emit;
    rtpcx->rtp_quit = quit;

    void **srtp_crypt = get_srtp_cryptos(sess);

    rtpcx->video.rtppx.crypx[0] = srtp_crypt[0];
    rtpcx->video.rtppx.crypx[1] = srtp_crypt[1];

    set_video_state(rtpcx, 2);

#ifdef VIDEO_VIA_FILE
    char *filepath = get_media_path();
    if( is_mp4_container(filepath) )
    {
        rtpcx->file_ctx = start_qt_client(rtpcx, filepath, 0, rtp_pump);
    }
    else if( is_ts_media_file(filepath) )
    {
        rtpcx->file_ctx = start_ts_client(rtpcx, filepath, 0, rtp_pump);
    }
    else
    {
        LOGI("[%s:%u] Unsupported media file [%s]\n",
            __func__, __LINE__, filepath);
    }
#endif

    return rtpcx;
}

// called from ice_halt_session()
void   rtp_media_reset(void *cx)
{
    rtpcx_t *rtpcx = cx;

#ifdef VIDEO_VIA_FILE
    char *filepath = get_media_path();
    if( is_mp4_container(filepath) )
    {
        close_qt_client(rtpcx->file_ctx);
    }
    else if( is_ts_media_file(filepath) )
    {
        close_ts_client(rtpcx->file_ctx);
    }
    rtpcx->file_ctx = 0;
#endif

    rtpcx->rtp_quit = 0;  // remove callback to ice_halt_session()
    rtp_joint_reset(rtpcx);
}

void   rtp_media_inlet(void *cx, void *pkt, int len)
{
    rtpcx_t *rtpcx = cx;

    rtppx_t *px = &(rtpcx->video.rtppx);

    px->rtcp_len = 0;

    if( len > 0 )
    {
        if( px->crypx[1] == 0 )
        {
            memcpy(px->rtcp_buf, pkt, len);
        }
        else
        {
            memcpy(px->in_crypted, pkt, len);
        }

        px->rtcp_len = len;
    }

    rtcp_handler(cx, px);
}

int   rtp_media_cntrl(void *cx, void *cmd)
{
    int e = 0;

    if( cmd == 0 )
    {
        return e;
    }

    LOGI("[%s:%u] VIDEO_VIA_MSDB not defined\n", __func__, __LINE__);

    return e;
}
////////////////////////////////////////////////////////////////////////////////

int  show_rtcp_rr(unsigned char *ptr, int len)
{
    if( len < sizeof(uint32_t) ) return -1;

    uint32_t receiver_ssrc = ntohl(*(uint32_t *)ptr);

    ptr += sizeof(uint32_t);
    len -= sizeof(uint32_t);

    while (len >= sizeof(rtcp_rr_t) )
    {
        rtcp_rr_t *rr = (void*) ptr;

        len -= sizeof(rtcp_rr_t);
        ptr += sizeof(rtcp_rr_t);

        unsigned char fraction_lost = rr->packet_lost.b[0];
        int cumul_lost = (rr->packet_lost.b[1]<<16)
                         + (rr->packet_lost.b[2]<<8) + rr->packet_lost.b[3];
        if( ntohl(rr->ssrc) == 0 ) continue;

        if( fraction_lost == 0 ) continue;

        LOGI("[%s:%u] receiver_ssrc=%.8x source_ssrc=%.8x lost=(%d %u)\n",
            __func__, __LINE__,
            receiver_ssrc, ntohl(rr->ssrc), cumul_lost, fraction_lost);

        LOGI("[%s:%u] last_seq=%.8x jitter=%.8x lst_sr=%.8x dlsr=%.8x\n",
            __func__, __LINE__,
            ntohl(rr->last_seq), ntohl(rr->jitter), ntohl(rr->lsr), ntohl(rr->dlsr));
    }

    return len;
}

int  show_rtcp_sr(void *ptr, int len)
{
    if( len < sizeof(rtcp_sr_info_t) ) return -1;

    rtcp_sr_info_t *sr = ptr;

    LOGI("[%s:%u] sender_ssrc=%.8x ntp_sec=%.8x ntp_frac=%.8x rtp_ts=%.8x\n",
        __func__, __LINE__,
        ntohl(sr->ssrc), ntohl(sr->ntp_sec), ntohl(sr->ntp_frac), ntohl(sr->rtp_ts));

    LOGI("[%s:%u] psent=%.8x osent=%.8x\n", __func__, __LINE__,
        ntohl(sr->psent), ntohl(sr->osent));

    return len - sizeof(rtcp_sr_info_t);
}

int  show_rtcp_sdes(void *ptr, int len)
{
    if( len < sizeof(uint32_t) ) return -1;

    uint32_t sender_ssrc = ntohl(*(uint32_t *)ptr);

    ptr += sizeof(uint32_t);
    len -= sizeof(uint32_t);

    if( len < sizeof(rtcp_sdes_item_t) ) return -1;

    rtcp_sdes_item_t *sdes = ptr;

    LOGI("[%s:%u] sender_ssrc=%.8x type=%u %.*s\n",
        __func__, __LINE__,
        sender_ssrc, sdes->type, sdes->length, sdes->data);

    return len - sizeof(rtcp_sdes_item_t);
}

int  show_rtcp_psfb(void *ptr, int len)
{
    uint32_t sender_ssrc = ntohl(*(uint32_t *)ptr);

    ptr += sizeof(uint32_t);
    len -= sizeof(uint32_t);

    uint32_t media_ssrc = ntohl(*(uint32_t *)ptr);

    ptr += sizeof(uint32_t);
    len -= sizeof(uint32_t);

    if( sender_ssrc || media_ssrc )
    {
        LOGI("[%s:%u] sender_ssrc=%.8x media_ssrc=%.8x fci_len=%d\n",
            __func__, __LINE__,
            sender_ssrc, media_ssrc, len);
    }
    return 0;
}

int  show_rtcp_packet(rtcp_t *rtcp, int len)
{
    while( len > 0 )
    {
        len -= sizeof(rtcp_common_t);

        if( len <= 0 ) break;

        unsigned char *ptr = (unsigned char*)(rtcp) + sizeof(rtcp_common_t);
        int siz = ntohs(rtcp->common.length)*4;

        switch( rtcp->common.pt )
        {
        case 200: // rfc3550: sender report
            show_rtcp_sr(ptr, siz);
            break;
        case 201: // rfc3550: receiver report
            show_rtcp_rr(ptr, siz);
            break;
        case 202: // rfc3550: SDES
            show_rtcp_sdes(ptr, siz);
            break;
        case 203: // rfc3550: bye
            break;
        case 205: // rfc4585: Transport layer FB message
            //LOGI("[%s:%u] RTPFB\n", __func__, __LINE__);
            break;
        case 206: // rfc4585: Payload-specific FB message
            //LOGI("[%s:%u] PSFB\n", __func__, __LINE__);
//            show_rtcp_psfb(ptr, siz);
            break;
        default:
            LOGI("[%s:%u] unknown pt=%u\n", __func__, __LINE__, rtcp->common.pt);
            break;
        }
        len -= rtcp->common.length*4;
    }

    return len;
}
////////////////////////////////////////////////////////////////////////////////
#ifdef LOCAL_BUILD

#include <signal.h>

static int g_quit;

static void sig_int(int sig)
{
    g_quit = 1;
}

__attribute__((weak))
int webrtc_send_utc(void *ice_sess, uint64_t utc)
{
    return 0;
}

__attribute__((weak))
extern void * get_srtp_cryptos(void *sess)
{
    static void * dumb[2]={(0)};
    return dumb;
}

int main(int argc, char *argv[])
{
    void   *rtpcx;
    rtpep_t video={.peer_addr=0, .self_addr=0, .rtp_ttl=5000,
                   .peer_port=0, .self_port=0, .self_ssrc=0x04030201, .pt=96};
    rtpep_t audio={.peer_addr=0, .self_addr=0,
                   .peer_port=0, .self_port=0, .self_ssrc=0x00030201, .pt=13};

    signal(SIGINT, sig_int);

    wcscpy(video.suid, DEMO_SUID);

    rtpcx = rtp_joint_setup(&video, &audio);

    set_video_state(rtpcx, 2);

    while( ! g_quit )
    {
        struct timespec tv={0, 200000000};
        nanosleep(&tv, 0);
    }

    LOGV("[%s:%u] sent %d packets or %d bytes\n", __func__, __LINE__, 
        ((rtpcx_t*)rtpcx)->video.rtppx.p_stats, ((rtpcx_t*)rtpcx)->video.rtppx.o_stats);

    rtp_joint_reset(rtpcx);

LOGV("[%s:%u] done..\n", __func__, __LINE__);
    return 0;
}

#endif  // LOCAL_BUILD

///////////////////////////////////////////////////////////////////////////////
#ifdef MPEG2_TS_DEMUXING

//
// return current time zone offset
// use 1970-01-02T00:00:00 to prevent invalid mktime()
//
static int  epoch_to_tz(void)
{
    struct tm day2 = { .tm_year = 70, .tm_mday = 2, .tm_isdst = -1 };

    return  (24*3600) - (int)mktime(&day2);
}

//
//  get seconds since epoch
//
static time_t iso8610_to_utc(char *iso)
{
    static int tz_set;
    static int tz_offset;
    struct tm utc = {0};

    if( ! tz_set )
    {
        tz_offset = epoch_to_tz();
        tz_set = 1;
    }

    sscanf(iso, "%4u-%2u-%2uT%2u:%2u:%2uZ",
           &utc.tm_year, &utc.tm_mon, &utc.tm_mday,
           &utc.tm_hour, &utc.tm_min, &utc.tm_sec);

    utc.tm_year -= 1900;
    utc.tm_mon -= 1;
    utc.tm_isdst = 0;

    return mktime(&utc) + tz_offset;
}

///////////////////////////////////////////////////////////////////////////////

// complete picture - out an rtp header before calling rtp_pmup()
//rtp_pump(cookie, rtpcx->h264_buf, rtpcx->h264_pnt);
static int prefix_and_send(rtpcx_t *rtpcx)
{
    cbx_t *cbx = get_demuxer_cbx(rtpcx->ts_demux, e_avc);
    if( cbx == 0 ) return -1;

    rtpcx->rtp_h264->rtp_hdr.seq = htons(rtpcx->h264_seq);
    rtpcx->rtp_h264->rtp_hdr.ts = htonl(cbx->pts/100LL*9LL); // to 90KHz
    // whole h264 frame in payload, set marker bit
    rtpcx->rtp_h264->rtp_hdr.m = 1;

    rtp_pump(rtpcx, rtpcx->rtp_h264, rtpcx->h264_pnt+sizeof(rtp_hdr_t));

    rtpcx->h264_seq += 1;
    rtpcx->h264_pnt = 0;

    return 0;
}

//
// feed packet to avc decoder
// nonzero @flag indicates end packet of a frame
// @len can be zero with @flag zero or nonzero
// @pkt null to indicate end-of-picture
//
static int avc_feed_packet(void *cookie, void *pkt, int len, int flag)
{
    rtpcx_t *rtpcx = cookie;

    if( rtpcx->rtp_h264 == 0 ) {return 0;}
    if( rtpcx->h264_pnt + len > rtpcx->h264_max) {
        // buffer overflow
        rtpcx->wait_idr = 1;  // ignore until next IDR frame
        LOGI("[%s:%u] WARNING: h264 buffer overflow\n", __func__, __LINE__);
        return -1;
    }

    // discard packet until first idr
    if( annex_b_idr(pkt, len) ) {
        // update video stream time
        if( rtpcx->video.vsutc != -1LL ) {
            int tick = sys_ticks_ms();
            rtpcx->video.vsutc += (tick - rtpcx->tick_txt);
            rtpcx->tick_txt = tick;
        }
        rtpcx->wait_idr = 0;
    } else if (rtpcx->wait_idr) {
        //LOGI("discard non-idr\n");
        return 0;
    }

    if( len > 0 ) {
        memcpy(rtpcx->rtp_h264->annex_b + rtpcx->h264_pnt, pkt, len);
        rtpcx->h264_pnt += len;
    } else if( rtpcx->h264_pnt > 0 ) {
        prefix_and_send(rtpcx);
    } else {}

    return len;
}

static void ts_aac_data(cbx_t *cbx)
{
    rtpcx_t *rtpcx = cbx->user;

    rtpcx->aac_stat += cbx->tail;

    if( rtpcx->sdb_sess ) {

        // send aac adts frame (partial) to transcoder
        aac_feed_stream(rtpcx->opus_ctx, cbx->data, cbx->tail);
    }

    cbx->tail = 0; // all consumed
}

static void ts_avc_data(cbx_t *cbx)
{
    rtpcx_t *rtpcx  = cbx->user;
    // ISO 14496-10 Annex B entails a frame delay in detecting end-of-frame

    rtpcx->avc_stat += cbx->tail;

    if (rtpcx->sdb_sess) {

        if (memcmp(cbx->data, "\x00\x00\x00\x01", 4) == 0) {

            avc_feed_packet(rtpcx, 0, 0, 1); // end of in-buffer frame
        }
        // feed to decoder
        avc_feed_packet(rtpcx, cbx->data, cbx->tail, 0);
    }
    cbx->tail = 0; // all consumed
}

static void ts_sub_text(cbx_t *cbx)
{
    rtpcx_t *rtpcx = cbx->user;

    char iso[24]={(0)};

    for(int k = 0; k < cbx->tail; k+=2) {
        // 2-byte unicode to ascii
        iso[k/2] = cbx->data[k+1];
    }

    if( rtpcx ) {
        rtpcx->video.vsutc = iso8610_to_utc(iso)*1000LL; // milliseconds
        rtpcx->tick_txt = sys_ticks_ms();
        rtpcx->txt_stat += cbx->tail;
    }

    cbx->tail = 0; // all consumed
}

// to be called from rtsp client
static void  make_ts_demux(void *cookie)
{
    cbx_t  *aac, *avc, *sub;
    void  *dmx;

    ((rtpcx_t*)cookie)->ts_demux = dmx = init_ts_demuxer((1<<10), (1<<20), 128);

    aac = get_demuxer_cbx(dmx, e_aac);
    aac->user = cookie;
    aac->call = ts_aac_data;
    avc = get_demuxer_cbx(dmx, e_avc);
    avc->user = cookie;
    avc->call = ts_avc_data;
    sub = get_demuxer_cbx(dmx, e_txt);
    sub->user = cookie;
    sub->call = ts_sub_text;
}

static void make_2435_ctx(void *cookie)
{
#if 0
    ((actx_t*)cookie)->mjpgx = init_2435_mjpeg(0); // default size

    set_jpg_handler(((actx_t*)cookie)->mjpgx, cookie, jpg_push_tojava);
#endif
}

// callback from rtsp client
static int sdp_ts_spec(void *cookie, char *sdp, int len)
{
    // check for rtp payload type 33 for mpeg ts
    if( 0 != strcasestr(sdp, "rtpmap:33") ) {
        LOGI("[sdp_ts_spec] rfc 2250 transport stream=%s\n", sdp);
        make_ts_demux(cookie);
    }
    else if( 0 != strcasestr(sdp, "rtpmap:26") ) {
        LOGI("[sdp_ts_spec] rfc 2435 jpeg stream=%s\n", sdp);
        make_2435_ctx(cookie);
    }
    else {
        LOGI("[sdp_ts_spec] unknown spec [%s]\n", sdp);
    }
    return 0;
}

///////////////////////////////////////////////////////////////////////////////

static int rtp_packets(void *cookie, void *pkt, int len)
{
    rtpcx_t *rtpcx = cookie;
    int      size = 0;

    // stat
    rtpcx->rtp_stat += len;

    if( len > 12 )
    {
        rtp_hdr_t *rtp = pkt;

        switch (((rtp_hdr_t *) pkt)->pt)
        {
        case 26: // rfc2435 jpeg
        #if 0  // ref jni-code.c
            len = rtp_payload(rtpcx, rtp, len); // wasteful in memcpy()
            feed_2435_mjpeg(rtpcx->mjpgx, rtp, len);
        #else
            LOGI("[%s:%u] PANIC!\n", __func__, __LINE__);
        #endif
            break;
        case 33: // rfc2250 transport stream
            if( rtpcx->ts_demux ) {
                int i = 12 + 4 * rtp->cc;
                if (rtp->x) {
                    unsigned char *ext = (unsigned char *) pkt + i;
                    // skip rtp header extension
                    i += 4 * (ext[2] * 256 + ext[3]) + 4;
                }
                if (len - i > 0) {
                    // NOTE: @size is never positive
                    size = feed_ts_demuxer(rtpcx->ts_demux, (char *) pkt + i, len - i);
                }
            }
            break;
        default:
            if( rtpcx->sdb_sess ) {  // native annex_b stream over rtp
                rtp_pump(rtpcx, pkt, len);
            }
            break;
        }
    }

    return size;
}

#endif // MPEG2_TS_DEMUXING
