// file : qtplayer.h
// date : 04/03/2023
#ifndef QTPLAYER_H_
#define QTPLAYER_H_

typedef int (*sdp_cb_t)(void *cookie, char *sdp, int len);
typedef int (*rtp_cb_t)(void *cookie, void *pkt, int len);

#ifdef __cplusplus
extern "C" {
#endif

    void * start_qt_client(void *cookie, char *path,
                             sdp_cb_t sdp_call, rtp_cb_t rtp_call);
    void   close_qt_client(void *media_ctx);
    int    check_qt_status(void *media_ctx);

    int    is_mp4_container(char *name);

#ifdef __cplusplus
}
#endif

#endif // QTPLAYER_H_
