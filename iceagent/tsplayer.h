// file : tsplayer.h
// date : 04/03/2023
#ifndef TSPLAYER_H_
#define TSPLAYER_H_

typedef int (*sdp_cb_t)(void *cookie, char *sdp, int len);
typedef int (*rtp_cb_t)(void *cookie, void *pkt, int len);

#ifdef __cplusplus
extern "C" {
#endif

    void * start_ts_client(void *cookie, char *path,
                             sdp_cb_t sdp_call, rtp_cb_t rtp_call);
    void   close_ts_client(void *media_ctx);
    int    check_ts_status(void *media_ctx);

    int    is_ts_media_file(char *name);

#ifdef __cplusplus
}
#endif

#endif // TSPLAYER_H_
