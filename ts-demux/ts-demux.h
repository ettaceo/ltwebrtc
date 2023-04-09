// file : tsdemux.h
// date : 11/26/2017
#ifndef TSDEMUX_H_
#define TSDEMUX_H_

typedef enum
{
    e_pat=0,
    e_pmt,
    e_aac,
    e_avc,
    e_txt,
    e_max

} e_pes_type;

typedef struct pes_t
{
    int   type;   // e_pes_type
    int   pid;
    unsigned long long pcr;
    unsigned long long pts;

}   pes_t;

// H.222 2.4.3
#define TS_PKT_SIZE 188

typedef struct cbx_t
{
    // callback, return 0 to conitnue, return positive to terminate
    int              (*call)(struct cbx_t *);
    void              *user;  // caller context
    unsigned long long pts;   // presentation timestamp
    int                mark;  // caller private. could pair with @tail
    int                work;  // initialized to 0 - for callee to use
    int                tail;  // data tail, set by caller, updated by callee
    int                size;  // buffer size
    unsigned char     *data;  // caller allocated buffer

}   cbx_t;

#ifdef __cplusplus
extern "C" {
#endif

    // parameters can be all zero
    void  *init_ts_demuxer(int aac_len, int avc_len, int txt_len);
    void   zero_ts_demuxer(void *dmx);
    void   free_ts_demuxer(void *dmx);
    cbx_t *get_demuxer_cbx(void *dmx, e_pes_type type);
    // @len must be multiple of TS_PKT_SIZE
    int    feed_ts_demuxer(void *dmx, void *pkt, int len);
    // return -1 if pid unknown, 0 if not a new frame, or 1 a new frame
    int    is_pes_boundary(void *dmx, e_pes_type type);
    int    pes_information(void *dmx, pes_t *pes);

#ifdef __cplusplus
}
#endif

#endif // TSDEMUX_H_
