// file : mediartp.h
// date : 04/26/2020
#ifndef MEDIARTP_H_
#define MEDIARTP_H_

#define VIDEO_VIA_FILE

#define RTP_CONFOR_NOISE_PT 13
#define RTP_H264_VIDEO_PT   96
#define RTP_OPUS_AUDIO_PT   98
#define RTP_SSRC_BE         0x73737263  // big-endian


typedef char               s8_t;
typedef unsigned char      u8_t;
typedef unsigned short     u16_t;
typedef short              s16_t;
typedef unsigned int       u32_t;
typedef int                s32_t;
typedef unsigned long long u64_t;
typedef long long          s64_t;

#ifdef __cplusplus
extern "C" {
#endif

void   rtp_media_reset(void *cx);

void   rtp_media_inlet(void *cx, void *pkt, int len);

void * rtp_media_setup(void *sess, int(*emit)(void*,void*,int),
                       void(*quit)(void*));

int    rtp_media_cntrl(void *cx, void *cmd);

#ifdef __cplusplus
}
#endif

#endif // MEDIARTP_H_
