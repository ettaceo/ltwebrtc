// file : tsplayer.c
// date : 04/03/2023

#include <stdio.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/timerfd.h>

#include "rfc_1889.h"
#include "ts-demux/ts-demux.h"
#include "tsplayer.h"

//#define LOGI(...)
#define LOGI printf
//#define LOGV(...)
#define LOGV printf

#define H264_FRAME_MAX (1<<21)

typedef struct sbuf_t
{
    rtp_hdr_t rtph;
    uint8_t   data[H264_FRAME_MAX];

}  sbuf_t;

typedef struct media_ctx_t
{
    void      *cookie;
    sdp_cb_t   sdp_call;
    rtp_cb_t   rtp_call;

    pthread_t  thread;

    int        status;
    int        timerfd;

    FILE   *mp4f;
    FILE   *tsfp;

    sbuf_t *sbuf;
    uint32_t   dlen;

    uint64_t   first_pts;
    uint64_t   frame_pts;
    uint32_t   loop_count;
    uint32_t   loop_time;
    uint32_t   frame_time;
    uint32_t   frame_count;

    uint32_t   ts;

    uint64_t   epoch_90khz;

    int    quit;

}  media_ctx_t;

enum
{
    e_invalid=0,
    e_errorconn,
    e_errorread,
    e_connected,
    e_connreset,
    e_status
};

#define TIMESPEC_TO_90KHZ(ts) ((ts).tv_sec*90000LL+((ts).tv_nsec*9LL/100000LL))

static uint64_t sys_ticks_90khz(media_ctx_t *ctx)
{
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    if( ctx->epoch_90khz == 0LL )
    {
        ctx->epoch_90khz = TIMESPEC_TO_90KHZ(tp);
    }

    return TIMESPEC_TO_90KHZ(tp) - ctx->epoch_90khz;
}

static int sys_wait_until(media_ctx_t *ctx, uint64_t ft)
{
    if( ctx->epoch_90khz == 0LL )
    {
        sys_ticks_90khz(ctx);
    }

    ft += ctx->epoch_90khz;

    struct timespec ts={ft/90000LL, (ft%9000)*100000/9};
    struct itimerspec its={.it_value=ts};
    int e = timerfd_settime(ctx->timerfd, TFD_TIMER_ABSTIME, &its, 0);
    if( e == 0 )
    {
        uint64_t tv;
        e = read(ctx->timerfd, &tv, sizeof(tv));
    }
    return e; // 8
}

static int avc_frame(cbx_t *cbx)
{
    media_ctx_t *ctx = cbx->user;

    if( cbx->mark == 0 ) return 0;

    if( ctx->frame_count == 0 )
    {
        ctx->first_pts = cbx->pts;
    }
    ctx->frame_pts = cbx->pts;

    ctx->frame_time = ctx->frame_pts - ctx->first_pts 
                    + ctx->loop_time * ctx->loop_count;

    uint32_t dlen = cbx->mark + sizeof(rtp_hdr_t);
    sbuf_t *sbuf = ctx->sbuf;
    uint16_t seq = ntohs(sbuf->rtph.seq);
    sbuf->rtph.m = 1;
    sbuf->rtph.seq = htons(seq + 1);
    sbuf->rtph.ts = htonl(ctx->frame_time);
    memcpy(sbuf->data, cbx->data, cbx->mark);

    // block until due time
    int e = sys_wait_until(ctx, ctx->frame_time);

    if( e > 0 && ctx->rtp_call )
    {
        ctx->rtp_call(ctx->cookie, (void *)sbuf, dlen);
    }
    ctx->frame_count += 1;

    return 0;
}

static int ts_avc_data(cbx_t *cbx)
{
    // ISO 14496-10 Annex B suggests a frame delay in detecting end-of-frame
    static char *startcode="\x00\x00\x00\x01";

    if( cbx->mark && memcmp(cbx->data + cbx->mark, startcode, 4) == 0 )
    {
        avc_frame(cbx);

        // move last packet to head
        memmove(cbx->data, cbx->data + cbx->mark, cbx->tail - cbx->mark);

        cbx->tail -= cbx->mark;
    }
    cbx->mark = cbx->tail;

    return 0;
}

static void * ts_reader_thread(void *media_ctx)
{
    media_ctx_t *ctx = media_ctx;
    void        *dmx;
    uint8_t      pkt[TS_PKT_SIZE];

    ctx->timerfd = timerfd_create(CLOCK_MONOTONIC, 0);

    dmx = init_ts_demuxer((1<<10), (1<<20), 128);

    // initialize rtp header
    sbuf_t *sbuf = ctx->sbuf;
    sbuf->rtph.version = 2;
    sbuf->rtph.pt = 96;
    sbuf->rtph.ssrc = 0xa0a0a0a0;

    while( ! ctx->quit )
    {
        cbx_t *avc = get_demuxer_cbx(dmx, e_avc);
        avc->call = ts_avc_data;
        avc->user = ctx;

        int e = 1;
        while( ctx->quit == 0 &&
               TS_PKT_SIZE == fread(pkt, 1, TS_PKT_SIZE, ctx->tsfp) )
        {
            if( (e = feed_ts_demuxer(dmx, pkt, TS_PKT_SIZE)) ) break;
        }

        ctx->loop_count += 1;
        ctx->loop_time = (3000 + ctx->frame_pts - ctx->first_pts);
        fseek(ctx->tsfp, 0, SEEK_SET);
        zero_ts_demuxer(dmx);
        //break;
    }

    free_ts_demuxer(dmx);

    close(ctx->timerfd);

    return 0;
}

void * start_ts_client(void *cookie, char *path,
                         sdp_cb_t sdp_call, rtp_cb_t rtp_call)
{
    media_ctx_t *ctx;

    ctx = calloc(1, sizeof(media_ctx_t)+sizeof(sbuf_t));

    ctx->sbuf = (void*)(ctx+1);

    ctx->cookie = cookie;

    ctx->sdp_call = sdp_call;
    ctx->rtp_call = rtp_call;
    
    ctx->status = e_invalid;

    ctx->tsfp = fopen(path, "rb");
    
    if( ctx->tsfp == 0 )
    {
        LOGI("[%s:%u] Unable to open [%s]!\n", __func__, __LINE__, path);
        free(ctx);
        return 0;
    }

    // create a thread to handle it
    pthread_create( &ctx->thread, 0, ts_reader_thread, ctx);

    return ctx;
}

void   close_ts_client(void *media_ctx)
{
    media_ctx_t *ctx = media_ctx;

    // it is possible @ctx=0 here, probably produced by over-sensitive ui
    if( ctx == 0 ) return;

    if( ctx->quit <= 0 )
    {
        if (ctx->quit == 0) ctx->quit = 1;

        pthread_kill(ctx->thread, SIGUSR1);

        LOGV("[%s:%u] close_file_client join thread\n", __func__, __LINE__);

        pthread_join(ctx->thread, 0);

        LOGV("[%s:%u] close_file_client join done\n", __func__, __LINE__);
    }

    if( ctx->tsfp )
    {
        fclose(ctx->tsfp);
    }
    free(ctx);

    LOGV("[%s:%u] ctx=%p freed\n", __func__, __LINE__, ctx);

    return;
}

int    check_ts_status(void *ctx)
{
    return (((media_ctx_t*)ctx)->quit == 0 || ((media_ctx_t*)ctx)->quit == 1);
}

int    is_ts_media_file(char *name)
{
    FILE *f = fopen(name, "rb");
    
    if( f == 0 ) return 0;

    unsigned char sync = 0;
    fread(&sync, 1, 1, f);
    size_t size = 0;
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fclose(f);
    
    return (size/188*188==size)&&(sync==0x47);
}

////////////////////////////////////////////////////////////////////////////////
#ifdef LOCAL_TEST

static int g_quit;
static void sig_int(int sig)
{
    g_quit = 1;
}

int main(int argc, char *argv[])
{
    if( argc < 2 )
    {
        printf("Usage:\t%s <media.ts>\n", argv[0]);
        return 0;
    }

    // use sigaction() so read() returns at SIGINT
    struct sigaction action;
    action.sa_handler = sig_int;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    sigaction(SIGINT, &action, NULL);

    void *u = start_file_client(0, argv[1], 0, 0);
    
    if( u ) while( g_quit == 0 )
    {
        sleep(1);
    }
    
    close_file_client(u);
    
    return 0;
}

#endif // LOCAL_TEST
