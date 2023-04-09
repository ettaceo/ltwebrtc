//
// file : qtplayer.c
// date : 03/03/13 04/03/2023
//
// differences between quicktime and mp4
// 1. ftyp - major type 'qt  ' v.s. 'mp42', etc.
// 2. hdlr - type = ['mhlr'|'dhlr'] v.s. zero fcc
//         - name using pascal string v.s. null-terminated string
// 3. minf - contains hdlr(dhlr) v.s. not
//
//                               
#pragma GCC diagnostic ignored "-Wmultichar"
#include <stddef.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <malloc.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <time.h>
#include <sys/timerfd.h>
#include <pthread.h>
#include <sched.h>

#include "rfc_1889.h"
#include "qtplayer.h"

typedef unsigned char u8_t;
typedef unsigned short u16_t;
typedef unsigned int u32_t;

//#define LOGI(...)
#define LOGI printf
//#define LOGV(...)
#define LOGV printf

#define MAX_PATH_LEN 256
#define TMP_FILE_LEN 8
//
// time difference between 1904 and 1970 in seconds
#define UTC1904TO70  0x7c25b080

static int g_is_quick_time=0;

// need to turn on pack91)
#pragma pack(1)

typedef struct atom_t 
{
    u32_t size;
    u32_t type;

}    atom_t;

// quicktime specific
typedef struct ftyp_t
{
    u32_t   size;
    u32_t   type;
    u32_t   mjor;  // major brand
    u32_t   mnor;  // minor version
    u32_t   join[4];  // compatible brand

}  ftyp_t;

typedef struct mvhd_t
{
    u32_t   size;
    u32_t   type;
    u32_t   version_flags;
    u32_t   create_time;
    u32_t   modify_time;
    u32_t   time_scale;
    u32_t   duration;
    u32_t   preferred_rate;
    u16_t   preferred_volume;
    u8_t    reserved[10];
    u32_t   matrix[9];
    u32_t   preview_time;
    u32_t   preview_duration;
    u32_t   poster_time;
    u32_t   selection_time;
    u32_t   selection_duration;
    u32_t   current_time;
    u32_t   next_track_id;

}    mvhd_t;

//
// sample description 
//
typedef struct stsd_t
{
    u32_t size;
    u32_t type;
    u32_t version_flags;
    int   entries;     // number of sample descriptions
    // for vdeo samples we expect 1 entry 
    // but conceptually it is possible to have
    // more than once sample descriptions - say the track
    // contains a sections, one mp4 and the other h264
}    stsd_t;

//
// video media sample descriptor 
//  - following standard sample description  stsd
//
typedef struct vmsd_t
{
    // common structure for all sample descriptors 
    u32_t   size;
    u32_t   data_format;   // 'mp4v' etc.
    u8_t    reserved[6];
    u16_t   data_ref_index;

    // video media specific
    u16_t   version;
    u16_t   rev_level;
    u32_t   vendor;
    u32_t   temporal_qulity;
    u32_t   spatial_quality;
    u16_t   width;
    u16_t   height;
    u32_t   h_resolution;
    u32_t   v_resolution;
    u32_t   data_size; // must be 0
    u16_t   frame_count; // usually 1
    u8_t    compressor[32]; // first byte = character count
    u16_t   depth;     // pixel color depth in bits
    u16_t   color_table_id;

}    vmsd_t;

//
// MPEG-4 Elementary Stream Descriptor
// required for mp4v as part of video media sample descriptor
//
// .mov
//   esds: len =74
//   esds: 03 80 80 80 45 00 00 10
//   esds: 04 80 80 80 3a 20 11 00
//   esds: 10 00 00 00 10 00 00 00
//   esds: 10 00 05 80 80 80 28 00
//   esds: 00 01 b0 01 00 00 01 b5
//   esds: 89 13 00 00 01 00 00 00
//   esds: 01 20 00 c4 88 80 0c e1
//   esds: 8a 02 1e 0a 31 00 00 01
//   esds: b2 33 69 76 78 40 a7 06
//   esds: 01 02
//
// .mp4 example
//   esds: len =57
//   esds: 03 37 00 00 1f 04 2f 20
//                               ^ objectProfileIndication: simple profile
//   esds: 11 02 ee 00 00 07 d0 00
//          
//   esds: 00 07 d0 00 05 20 00 00
//   esds: 01 b0 f3 00 00 01 b5 0e
//   esds: e0 40 c0 cf 00 00 01 00
//   esds: 00 00 01 20 00 84 40 fa
//   esds: 28 2f a0 f0 a2 1f 06 01
//   esds: 02
// search 14496-1 14496-14 for "elementary stream descriptor"
// 0x03 - ES_DescrTag
//   [80 80 80] <length> <ED_ID><streamPriority>
//   <DecoderConfigDescriptor><SLConfigDescriptor>
// 0x04 - DecoderConfigDescrTag
//   [80 80 80] <length>..
// 0x06 - SLConfigDescrTag
//   <length> 02  = 02 = reserved for iso use
//
typedef struct esds_t
{
    u32_t   size;
    u32_t   type;
    u32_t   version_flags; // 
    u8_t    esds[0];       // use @size to determine array length

}    esds_t;

#define NTOH16(w) ((((w)&0xff)<<8)|(((w)>>8)&0xff))
#define HTON16(d) NTOH16(d)
#define NTOH32(d) ((NTOH16((d)&0xffff)<<16)|NTOH16(((d)>>16)&0xffff))
#define HTON32(d) NTOH32(d)

static char* qtos(char *t, int q)
{
    static char s[5];
    if( t == 0 ) t = s;
    memcpy(t, &q, 4);
    t[4] = '\0';
    return t;
}

__attribute__((unused))
static int  is_video_codec(int code)
{
    char t[5]={0};
    if( code == 'mp4v' ) return 1;
    if( code == 'jpeg' ) return 1;
    if( code == 'avc1' ) return 1;
    printf("[%s] [%s] not a video\n", __FUNCTION__, qtos(t, HTON32(code)));
    return 0;
}

__attribute__((unused))
static void show_atom(int o, atom_t *a, int depth)
{
    char t[5];
    int  j;

    printf("[%.8d] ", o);
    for( j=0; j < depth; j++) printf(" ");
    printf("type=%s(%.8x) size=%d\n", qtos(t, a->type), a->type, NTOH32(a->size));
}

////////////////////////////////////////////////////////////////////////////////

#define ERR_POINT -(__LINE__)

typedef int (*sdp_cb_t)(void *cookie, char *sdp, int len);
typedef int (*rtp_cb_t)(void *cookie, void *pkt, int len);

#define H264_FRAME_MAX (1<<21)
#define H264_SPS_PPS_MAX  64
#define STTS_MAX_COUNT  8

typedef struct sbuf_t
{
    rtp_hdr_t rtph;
    uint8_t   data[H264_FRAME_MAX];

}  sbuf_t;

typedef struct avc1_t
{
    uint64_t  offset_to_stsc;
    uint64_t  offset_to_stts;
    uint64_t  offset_to_stss;
    uint64_t  offset_to_stco;
    uint32_t *sample_to_chunk;
    uint32_t *sample_size;
    //uint32_t *time_to_sample;
    struct stts_entry {
        uint32_t count;
        uint32_t duration_90khz;
    } * time_to_sample;
    uint32_t  stts_entries;
    uint32_t  chunk_offset;
    uint32_t  sample_count;
    uint32_t  chunk_number;

    int       timerfd;

    uint32_t  loop_count;
    uint32_t  frame_count;
    uint32_t  frame_index;
    uint32_t  sync0_index; // first sync sample number

    uint64_t  frame_time;
    uint64_t  epoch_90khz;

    int       sps_pps_size;
    uint8_t   sps_pps_text[H264_SPS_PPS_MAX];

    void      *cookie;
    sdp_cb_t   sdp_call;
    rtp_cb_t   rtp_call;
    pthread_t  thread;

    sbuf_t   *sbuf;

    FILE    **file;  // point to mp4x->file

    int      *quit;

}  avc1_t;

typedef struct mp4x_t
{
    int        quit;
    int        nfcc;
    uint32_t   fccs[2];

    int        is_video_track;
    int        enter_mdia;
    uint32_t   media_type; // subcomponent 'vide'
    int        enter_stbl;
    uint32_t   global_timescale;
    uint32_t   stsd_data_format; // 'avc1'

    avc1_t    *avc1;

    FILE      *file;

    pthread_t  thread;

}  mp4x_t;

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

//
// expect to match supported four-character-codes
//
static int  proc_ftyp(mp4x_t *mp4x, int size)
{
    int  brand='    ';
    int  version=0;
    char t[5]={0};

    size -= sizeof(atom_t);

    fread(&brand, 1, 4, mp4x->file);
    size -= 4;

    fread(&version, 1, 4, mp4x->file);
    size -= 4;

    g_is_quick_time = (brand == HTON32('qt  '));
    LOGV(" FTYP: %s.%x\n", qtos(t, brand), version);

    int matched = 0;
    int k;

    while( size >= 4 )
    {
        fread(&brand, 1, 4, mp4x->file);
        size -= 4;
        //printf("FTYP:  compatibe %s\n", qtos(t, brand));
        for( k=0; k < mp4x->nfcc; k++ )
        {
            if( brand == mp4x->fccs[k] ) matched += 1;
        }
    }

    return (matched == mp4x->nfcc) ? 0 : ERR_POINT;
}

__attribute__((unused))
static void proc_tkhd(mp4x_t *mp4x, int size)
{
    int  quad[21]={0};

    size -= sizeof(atom_t);

    fread(quad, 1, 84, mp4x->file);
    size -= 84;

    // quad[8] lo 16-bit: alternative group   
    //mp4x->is_video_track = (NTOH32(quad[8])&0xffff) == 0 ? 1 : 0;
}

static void proc_hdlr(mp4x_t *mp4x, int size)
{
    int   quad[3];

    fread(quad, 1, sizeof(quad), mp4x->file);
    size -= size;

    mp4x->media_type = 0;

    if( mp4x->enter_mdia )
    {
        mp4x->media_type = HTON32(quad[2]);
    }
    if( mp4x->media_type == 'vide' )
    {
        LOGV("[%s:%u HDLR subtype=%s \n", __func__, __LINE__, qtos(0, quad[2]));
    }
}

static void proc_mdhd(mp4x_t *mp4x, int size)
{
    int  quad[8]={0};

    size -= sizeof(atom_t);

    fread(quad, 1, 24, mp4x->file);
    size -= 24;
    mp4x->global_timescale = NTOH32(quad[3]);

    LOGV("[%s:%u MDHD: timescale=%d duration=%x\n", __func__, __LINE__,
        mp4x->global_timescale, NTOH32(quad[4]));
}

static void proc_mvhd(mp4x_t *mp4x, int size)
{
    int  quad[25]={0};
    time_t utc=0;

    size -= sizeof(atom_t);

    fread(quad, 1, 100, mp4x->file);
    size -= 100;

    utc = NTOH32(quad[1]) - UTC1904TO70;
    printf(" MVHD: create time=%s", ctime(&utc));
    utc = NTOH32(quad[2]) - UTC1904TO70;
    printf(" MVHD: modify time=%s", ctime(&utc));
    printf(" MVHD: timescale=%d\n", NTOH32(quad[3]));
    printf(" MVHD: duration=%d=%dms\n",
        NTOH32(quad[4]), NTOH32(quad[4])/NTOH32(quad[3])*1000);
    mp4x->global_timescale = NTOH32(quad[3]);
    printf(" MVHD: matrix=%x %x %x %x %x %x %x %x %x\n",
        quad[9], quad[10], quad[11], quad[12], quad[13], quad[14],
        quad[15], quad[16], quad[17]);

}

static int proc_avcc(mp4x_t *mp4x, uint8_t *avcC, int len)
{    
    if( len <= 6 /*sizeof(avcC_t)*/ )
    {
         return ERR_POINT;
    }
    avcC += 6; //sizeof(avcC_t)
    len -= 6;  //sizeof(avcC_t)
    
    int sps_len = avcC[0]*256 + avcC[1];
    if( 2 + sps_len + 2 >= len)
    {
         return ERR_POINT;
    }
    if( avcC[2 + sps_len] != 1 )
    {
         return ERR_POINT; // one pps only
    }
    int pps_len = avcC[2 + sps_len +1]*256 + avcC[2 + sps_len +2];
    
    if( 2 + sps_len + 3 + pps_len > len )
    {
        LOGV("[%s:%u]  2 + %d + 3 + %d > %d\n", __func__, __LINE__,
            sps_len, pps_len, len);
         return ERR_POINT;
    }
    
    if( 4 + sps_len + 4 + pps_len > H264_SPS_PPS_MAX )
    {
         return ERR_POINT;
    }
    avc1_t *avc = mp4x->avc1;
    memcpy(avc->sps_pps_text, "\x00\x00\x00\x01", 4);
    memcpy(avc->sps_pps_text+4, avcC+2, sps_len);
    memcpy(avc->sps_pps_text+4+sps_len, "\x00\x00\x00\x01", 4);
    memcpy(avc->sps_pps_text+4+sps_len+4, avcC+2+sps_len+3, pps_len);

    avc->sps_pps_size = 4 + sps_len + 4 + pps_len;
    
    return 0;
}

static int proc_vmsd(mp4x_t *mp4x, int size)
{
    atom_t  atom;
    vmsd_t  vmsd;
    int     vmsz;
//    char t[5]={0};

    // get size of video media specif part
    vmsz = sizeof(vmsd_t) - offsetof(vmsd_t, version);

    while( size >= 8 )
    {
        // read video media specific part
        fread(&vmsd.version, 1, vmsz, mp4x->file);
        size -= vmsz;
/*
        printf("  VMSD: version(%d) rev(%d)\n",
            NTOH16(vmsd.version), NTOH16(vmsd.rev_level));
        printf("  VMSD: temporal_qulity(%d) spatial_quality(%d)\n",
            NTOH32(vmsd.temporal_qulity), NTOH32(vmsd.spatial_quality));

        printf("  VMSD: vendor(%s)\n", qtos(t, vmsd.vendor));
        printf("  VMSD: width(%d) height(%d) depth(%d)\n",
            NTOH16(vmsd.width), NTOH16(vmsd.height), NTOH16(vmsd.depth));
        printf("  VMSD: hres(%d) vres(%d)\n",
            NTOH32(vmsd.h_resolution)>>16, NTOH32(vmsd.v_resolution)>>16);
        printf("  VMSD: compressor=%s\n", vmsd.compressor+1);
        printf("  VMSD: frame_count(%d) color_table_id(%d)\n",
            NTOH16(vmsd.frame_count), NTOH16(vmsd.color_table_id));
*/
        // read extendions
        while( size >= sizeof(atom_t) )
        {
            fread(&atom, 1, sizeof(atom_t), mp4x->file);
/*
            printf("  VMSD: extension(%s) size=%d out of %d\n", 
                qtos(t, atom.type), NTOH32(atom.size), size);
*/
            int len;
            if( NTOH32(atom.type) == 'avcC' &&
                (len = (NTOH32(atom.size)) - sizeof(atom_t)) > 0 )
            {
                unsigned char *avcc = __builtin_alloca(len);
                fread(avcc, 1, len, mp4x->file);
                int e = proc_avcc(mp4x, avcc, len);
                //dump_hex(avcc, len);
                if( e != 0 ) return e;
            }
            size -= NTOH32(atom.size);
            break;
        }
    }
    return 0;
}

static int proc_stsd(mp4x_t *mp4x, int size)
{
    mp4x->stsd_data_format = 0;

    if( mp4x->media_type != 'vide' )
    {
        return 0;
    }

    int e = 0;
    int  quad[4]={0};
    size -= sizeof(atom_t);
    fread(quad, 1, 8, mp4x->file);
    size -= 8;

    LOGV("[%s:%u] STSD %d entries\n", __func__, __LINE__, NTOH32(quad[1]));

    mp4x->stsd_data_format = 0;

    if( size >= 16 )
    {
        fread(quad, 1, 16, mp4x->file);

        mp4x->stsd_data_format = NTOH32(quad[1]);

        LOGV("[%s:%u] Data Format %s\n", __func__, __LINE__, qtos(0, quad[1]));

        if( is_video_codec(NTOH32(quad[1])) ) 
        {
            e = proc_vmsd(mp4x, size - 16);
        }

        size -= NTOH32(quad[0]);
    }
    return e;
}

static int proc_stss(mp4x_t *mp4x, int size)
{
    if( mp4x->stsd_data_format != 'avc1' )
    {
        return 0;
    }

    int  quad[4]={0};
    size -= sizeof(atom_t);
    fread(quad, 1, 8, mp4x->file);
    size -= 8;
    uint32_t entries = NTOH32(quad[1]);

    if( entries > 0 )
    {
        fread(quad, 1, 4, mp4x->file);
        mp4x->avc1->sync0_index = NTOH32(quad[0]);
    }
    if(  mp4x->avc1->sync0_index > 0 )
    {
        // from sample number to sample index
        mp4x->avc1->sync0_index -= 1;
    }
LOGV("[%s:%u] STSS entries=%d sync0_index=%d\n",
    __func__, __LINE__, entries, mp4x->avc1->sync0_index);

    mp4x->avc1->sync0_index = 0; // !
    return 0;
}

static int proc_stts(mp4x_t *mp4x, int size)
{
    if( mp4x->stsd_data_format != 'avc1' )
    {
        return 0;
    }

    int  quad[4]={0};
    size -= sizeof(atom_t);
    fread(quad, 1, 8, mp4x->file);
    size -= 8;
/*
    if( NTOH32(quad[1]) != 1 || size < 8 )
    {
        LOGV("[%s:%u] STTS: not support more than 1 entries(%d)\n",
            __func__, __LINE__, NTOH32(quad[1]));
        return ERR_POINT;
    }
*/
    avc1_t *avc = mp4x->avc1;

    avc->stts_entries = NTOH32(quad[1]);
    avc->time_to_sample =
        __builtin_calloc(1, sizeof(struct stts_entry) * avc->stts_entries);

    uint32_t sample_count = 0;
    int i=0;

    //while( size >= 8 )
    for( i = 0; i < avc->stts_entries; i+=1 )
    {
        fread(quad, 1, 8, mp4x->file);
        size -= 8;

        avc->time_to_sample[i].count = NTOH32(quad[0]);

        u32_t duration = (mp4x->global_timescale > 0 ? 
                      (NTOH32(quad[1])*1000)/mp4x->global_timescale:1000);
        avc->time_to_sample[i].duration_90khz = duration * 90;

        sample_count += avc->time_to_sample[i].count;
    }

    if( avc->sample_count == 0 )
    {
        avc->sample_count = sample_count;
    }

    LOGV("[%s:%u] Sample Count(%d)\n", __func__, __LINE__, avc->sample_count);

    return 0;
}

static int proc_stsc(mp4x_t *mp4x, int size)
{
    if( mp4x->stsd_data_format != 'avc1' )
    {
        return 0;
    }

    int  quad[4]={0};
    size -= sizeof(atom_t);
    fread(quad, 1, 8, mp4x->file);
    size -= 8;

    if( NTOH32(quad[1]) != 1 || size < 12 )
    {
        LOGV("[%s:%u] STSC: not support more than 1 entries(%d)\n",
            __func__, __LINE__, NTOH32(quad[1]));
        return ERR_POINT;
    }

    while( size > 0 )
    {
        fread(quad, 1, 12, mp4x->file);
        size -= 12;

        LOGV(" Start Chunk(%d) Samples(%d) ID(%d)\n", 
            NTOH32(quad[0]), NTOH32(quad[1]), NTOH32(quad[2]));
        break; // one entry
    }

    avc1_t *avc = mp4x->avc1;

    if( avc->sample_count == 0 )
    {
        avc->sample_count = NTOH32(quad[1]);
    }
 
    if( NTOH32(quad[1]) != avc->sample_count )
    {
        LOGV("[%s:%u] STSC: sample count mistmatch(%d %d)\n",
            __func__, __LINE__, NTOH32(quad[1]), avc->sample_count);
        return ERR_POINT;
    }
    
    avc->chunk_number = NTOH32(quad[0]);

    return 0;
}

static int proc_stco(mp4x_t *mp4x, int size)
{
    if( mp4x->stsd_data_format != 'avc1' )
    {
        return 0;
    }

    int  quad[4]={0};
    size -= sizeof(atom_t);
    fread(quad, 1, 8, mp4x->file);
    size -= 8;

    uint32_t entries = NTOH32(quad[1]);
    if( entries != 1 )
    {
        LOGV("[%s:%u] STCO: not support more than 1 entries(%d)\n",
            __func__, __LINE__, entries);
        return ERR_POINT;
    }
    if( size / 4 != entries )
    {
        LOGV("[%s:%u] STCO: not support 64-bit offset yet (%u %u)\n",
            __func__, __LINE__, size/4, entries);
        return ERR_POINT;
    }

    avc1_t *avc = mp4x->avc1;

    fread(quad, 1, 4, mp4x->file);
    
    avc->chunk_offset = NTOH32(quad[0]);

    LOGV("[%s:%u] STCO: chunk-offset=%u\n",
            __func__, __LINE__, avc->chunk_offset);

    return 0;
}

static int proc_stsz(mp4x_t *mp4x, int size)
{
    if( mp4x->stsd_data_format != 'avc1' )
    {
        return 0;
    }

    int  quad[8]={0};
    int  entries;
    size -= sizeof(atom_t);
    // flags and entries
    fread(quad, 1, 12, mp4x->file);
    size -= 12;

    int smplsiz = NTOH32(quad[1]);
    
    if( smplsiz != 0 )
    {
        LOGI("[%s:%u] STSZ: bad sample size %u\n",
            __func__, __LINE__, smplsiz);
        return ERR_POINT;
    }
    entries = NTOH32(quad[2]);
    if( entries > size/4 )
    {
        LOGI("[%s:%u] STSZ: bad atom size (%d)/4 < entries=%u\n",
            __func__, __LINE__,size, entries);
        return ERR_POINT;
    }
    avc1_t *avc = mp4x->avc1;

    if( avc->sample_count == 0 )
    {
        avc->sample_count = entries;
    }
    if( entries != avc->sample_count )
    {
        LOGV("[%s:%u] STSZ:sample count mismatch(%u %u)\n",
            __func__, __LINE__, avc->sample_count, entries);
        return ERR_POINT;
    }

    avc->sample_size = __builtin_malloc(sizeof(uint32_t)*entries);

    int i = 0;
    while( size > 0 && i < avc->sample_count)
    {
        fread(quad, 1, 4, mp4x->file);
        size -= 4;
        avc->sample_size[i] = NTOH32(quad[0]);
        i += 1;
    }
    if( i < avc->sample_count )
    {
        LOGV("[%s:%u] STSZ:sample count mismatch(%u %u)\n",
            __func__, __LINE__, avc->sample_count, i);

        return ERR_POINT;
    }
/*
    for( i=0; i < avc->sample_count; i+=1 )
    {
        LOGV("[%s:%u] STSZ:sample-size[%u]= %u\n",
            __func__, __LINE__, i, avc->sample_size[i]);
    }
*/
    return 0;
}

//
//  return atom size or error
//
static int qt_parser(mp4x_t *mp4x, unsigned int start, int depth)
{
    atom_t       atom;
    int          asize;
    int          bsize;
    int          error=0;

    fseek(mp4x->file, start, SEEK_SET);

    fread(&atom, 1, sizeof(atom_t), mp4x->file);

    asize = NTOH32(atom.size);

    show_atom(start, &atom, depth);

    switch( atom.type )
    {
    case NTOH32('ftyp'):
        error = proc_ftyp(mp4x, asize);
        break;
    case NTOH32('mdhd'):
        proc_mdhd(mp4x, asize);
        break;
    case NTOH32('mvhd'):
        proc_mvhd(mp4x, asize);
        break;
    case NTOH32('stsd'):
        error = proc_stsd(mp4x, asize);
        break;
    case NTOH32('stts'):
        error = proc_stts(mp4x, asize);
        break;
    case NTOH32('stsc'):
        error = proc_stsc(mp4x, asize);
        break;
    case NTOH32('stco'):
        error = proc_stco(mp4x, asize);
        break;
    case NTOH32('stss'):
        proc_stss(mp4x, asize);
        break;
    case NTOH32('stsz'):
        error = proc_stsz(mp4x, asize);
        break;
    case NTOH32('hdlr'):
        proc_hdlr(mp4x, asize);
        break;
    default: break;
    }

    if( error )
    {
        LOGV("[%s:%u] error=%d\n", __func__, __LINE__, error);

        return error;
    }

    switch( atom.type )
    {
    // containers
    case NTOH32('moov'):
    case NTOH32('trak'):
    case NTOH32('edts'):
    case NTOH32('mdia'):
    case NTOH32('minf'):
    //case NTOH32('dinf'):
    case NTOH32('stbl'):
        bsize = 8;
        break;
    default:
        bsize = asize;
        break;
    }
    
    switch( atom.type )
    {
    case HTON32('mdia'):
        LOGV("[%s:%u] enter mdia\n", __func__, __LINE__);
        mp4x->enter_mdia = 1;
        break;
    case HTON32('stbl'):
        if( mp4x->enter_mdia ) mp4x->enter_stbl = 1;
        break;
    default:
        break;
    }

    while( bsize < asize )
    {
        // recursive
        int e = qt_parser(mp4x, start+bsize, depth+1);
        if( e <= 0 ) return e;
        bsize += e;
    }

    switch( atom.type )
    {
    case HTON32('mdia'):
        LOGV("[%s:%u] exit mdia\n", __func__, __LINE__);
        mp4x->enter_mdia = 0;
        break;
    case HTON32('stbl'):
        mp4x->enter_stbl = 0;
        break;
    default:
        break;
    }

    return asize;
}

////////////////////////////////////////////////////////////////////////////////

#define TIMESPEC_TO_90KHZ(ts) ((ts).tv_sec*90000LL+((ts).tv_nsec*9LL/100000LL))

static uint64_t sys_ticks_90khz(avc1_t *ctx)
{
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    if( ctx->epoch_90khz == 0LL )
    {
        ctx->epoch_90khz = TIMESPEC_TO_90KHZ(tp);
    }

    return TIMESPEC_TO_90KHZ(tp) - ctx->epoch_90khz;
}

static int sys_wait_until(avc1_t *ctx, uint64_t ft_90khz)
{
    if( ctx->epoch_90khz == 0LL )
    {
        sys_ticks_90khz(ctx);
    }

    ft_90khz += ctx->epoch_90khz;

    struct timespec ts={ft_90khz/90000LL, (ft_90khz%90000LL)*100000/9};
    struct itimerspec its={.it_value=ts};
    int e = timerfd_settime(ctx->timerfd, TFD_TIMER_ABSTIME, &its, 0);
    if( e == 0 )
    {
        uint64_t tv;
        e = read(ctx->timerfd, &tv, sizeof(tv));
    }
    return e; // 8
}

static uint32_t sample_guration(avc1_t *avc, uint32_t index)
{
    // index < sample count
    int i;
    for( i = 0; i < avc->stts_entries; i++ )
    {
        if( index < avc->time_to_sample[i].count )
        {
            return avc->time_to_sample[i].duration_90khz;
        }
        index -= avc->time_to_sample[i].count;
    }
    
    return ~0; // error
}

static int  get_next_sample(avc1_t *avc)
{
    if( avc->frame_index <= avc->sync0_index )
    {
        uint32_t offset = avc->chunk_offset;
        int i;
        for(i = 0; i < avc->sync0_index; i++)
        {
            offset += avc->sample_size[i];
        }
        fseek(avc->file[0], offset, SEEK_SET);
        
        avc->frame_index = avc->sync0_index;
    }
//LOGV("[%s:%u] frame-count=%d frame_index=%u\n", __func__, __LINE__, avc->frame_count, avc->frame_index);

    int len, size = avc->sample_size[avc->frame_index];

    len = fread(avc->sbuf->data, 1, size, avc->file[0]);

    if( len != size)
    {
        LOGV("[%s:%u] read samlple(%d) error(%d %d)\n", __func__, __LINE__,
            avc->frame_index, len, size);
        return ERR_POINT;
    }
    // in case of <sei><idr>
    int lead = NTOH32(((uint32_t*)avc->sbuf->data)[0]);
    if( lead + 4 < len )
    {
        len -= lead + 4;
        memmove(avc->sbuf->data, avc->sbuf->data + lead+4, len);
    }

if( (avc->sbuf->data[4]&0x1f)!= 1 )
{
//dump_hex(avc->sbuf->data, 30);
}

    memcpy(avc->sbuf->data, "\x00\x00\x00\x01", 4);

    if( (avc->sbuf->data[4] & 0x1f) == 0x05 )
    {
        memmove(avc->sbuf->data + avc->sps_pps_size, avc->sbuf->data, len);
        memcpy(avc->sbuf->data, avc->sps_pps_text, avc->sps_pps_size);
        len += avc->sps_pps_size;
    }

    avc->frame_time += sample_guration(avc, avc->frame_index);

    avc->frame_index += 1;
    if( avc->frame_index >= avc->sample_count )
    {
        avc->loop_count += 1;
        avc->frame_index = 0;
    }

    avc->frame_count += 1;

    return len;
}

static void * qt_player(void *avc)
{
    avc1_t *ctx = avc;

    ctx->timerfd = timerfd_create(CLOCK_MONOTONIC, 0);

    sbuf_t *sbuf = ctx->sbuf;
    sbuf->rtph.version = 2;
    sbuf->rtph.pt = 96;
    sbuf->rtph.ssrc = 0xa0a0a0a0;

    uint32_t len;
    while( ctx->quit[0] == 0 && 0 < (len =  get_next_sample(ctx)) )
    {
        uint16_t seq = HTON16(sbuf->rtph.seq);
        sbuf->rtph.seq = HTON16(seq + 1);
        sbuf->rtph.ts = HTON32(ctx->frame_time);
        sbuf->rtph.m = 0x01;
        if( ctx->rtp_call )
        {
            ctx->rtp_call(ctx->cookie, (void *)sbuf, len+sizeof(rtp_hdr_t));
        }
        // block until due time
        int e = sys_wait_until(ctx, ctx->frame_time);
        (void)e;
//if( ctx->frame_count > 5) break;
    }

    close(ctx->timerfd);

    LOGV("[%s:%u] frame-count=%d exit\n", __func__, __LINE__, ctx->frame_count);
    return 0;
}

void * start_qt_client(void *cookie, char *path,
                         sdp_cb_t sdp_call, rtp_cb_t rtp_call)
{
    size_t   max = sizeof(mp4x_t) + sizeof(avc1_t) + sizeof(sbuf_t);
    mp4x_t  *ctx = __builtin_malloc(max);
    memset(ctx, 0, max);
    ctx->avc1 = (void *)(ctx + 1);
    ctx->avc1->sbuf = (void *)(ctx->avc1 + 1);
    ctx->nfcc=1,
    ctx->fccs[0]=HTON32('avc1');

    ctx->avc1->cookie = cookie;
    ctx->avc1->sdp_call = sdp_call;
    ctx->avc1->rtp_call = rtp_call;
    ctx->avc1->quit = &ctx->quit;

    unsigned int fsize;

    ctx->file = fopen(path, "rb");

    if( ctx->file == 0 )
    {
        LOGI("[%s:%u] Unable to open [%s]!\n", __func__, __LINE__, path);
        free(ctx);
        return 0;
    }

    fseek(ctx->file, 0, SEEK_END);
    fsize = ftell(ctx->file);
    fseek(ctx->file, 0, SEEK_SET);

    unsigned int offset;
    int e;

    for( offset = 0; offset < fsize; )
    {
        e = qt_parser(ctx, offset, 0);

        if( e <= 0) break;

        offset += e;
    }

    if( e < 0 )
    {
        LOGI("[%s:%u] error point=%d\n", __func__, __LINE__, e);
        fclose(ctx->file);
        free(ctx);
        return 0;
    }

    ctx->avc1->file = &(ctx->file);

    pthread_attr_t attr;
    struct sched_param param;
    // set sched priority
    e = pthread_attr_init (&attr);
    e = pthread_attr_getschedparam (&attr, &param);
    param.sched_priority = SCHED_RR; // SCHED_RR SCHED_FIFO
    e = pthread_attr_setschedparam (&attr, &param);
    e = pthread_create(&ctx->thread, &attr, qt_player, ctx->avc1);

    return ctx;
}

void   close_qt_client(void *mp4x)
{
    mp4x_t *ctx = mp4x;

    // it is possible @ctx=0 here, probably produced by over-sensitive ui
    if( ctx == 0 ) return;

    if( ctx->quit <= 0 )
    {
        if (ctx->quit == 0) ctx->quit = 1;

        pthread_kill(ctx->thread, SIGUSR1);

        LOGV("[%s:%u] close_qt_client join thread\n", __func__, __LINE__);

        pthread_join(ctx->thread, 0);

        LOGV("[%s:%u] close_qt_client join done\n", __func__, __LINE__);
    }

    fclose(ctx->file);

    if( ctx->avc1->time_to_sample )
    {
        __builtin_free(ctx->avc1->time_to_sample);
    }
    if( ctx->avc1->sample_size )
    {
        __builtin_free(ctx->avc1->sample_size);
    }
    __builtin_free(ctx);

    LOGV("[%s:%u] ctx=%p freed\n", __func__, __LINE__, ctx);

    return;
}

int    check_qt_status(void *ctx)
{
    return (((mp4x_t*)ctx)->quit == 0 || ((mp4x_t*)ctx)->quit == 1);
}


int  is_mp4_container(char *name)
{
    int e = 0;
    FILE *f = fopen(name, "rb");

    if( f == 0 ) return 0;

    atom_t       atom;
    int          size;

    fread(&atom, 1, sizeof(atom_t), f);

    if( atom.type != HTON32('ftyp') ) goto exit;

    size = NTOH32(atom.size);

    int  brand='    ';
    int  version=0;

    size -= sizeof(atom_t);

    if( size < 8 ) goto exit;

    fread(&brand, 1, 4, f);
    size -= 4;

    fread(&version, 1, 4, f);
    size -= 4;

    while( e == 0 && size >= 4 )
    {
        fread(&brand, 1, 4, f);
        size -= 4;
        e = (brand == HTON32('avc1'));
    }

exit:
    fclose(f);

    return e;
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
        printf("Usage\t %s <path>\n", argv[0]);
        return 0;
    }
    signal(SIGINT, sig_int);

    mp4x_t  *mp4x= __builtin_malloc(sizeof(mp4x_t) + sizeof(avc1_t) + sizeof(sbuf_t));
    memset(mp4x, 0, sizeof(mp4x_t) + sizeof(avc1_t) + sizeof(sbuf_t));
    mp4x->avc1 = (void *)(mp4x + 1);
    mp4x->avc1->sbuf = (void *)(mp4x->avc1 + 1);
    mp4x->nfcc=1,
    mp4x->fccs[0]=HTON32('avc1');

    unsigned int offset;
    unsigned int fsize;

    mp4x->file = fopen(argv[1], "rb");

    if( mp4x->file == 0 ) goto exit;

    fseek(mp4x->file, 0, SEEK_END);
    fsize = ftell(mp4x->file);
    fseek(mp4x->file, 0, SEEK_SET);

    int e;

    for( offset = 0; offset < fsize; )
    {
        e = qt_parser(mp4x, offset, 0);

        if( e <= 0) break;

        offset += e;
    }

    if( e < 0 )
    {
        LOGI("[%s:%u] error point=%d\n", __func__, __LINE__, e);
    }

    avc1_t *avc = mp4x->avc1;
    avc->file = &mp4x->file;
    avc->quit = &g_quit;
    
    e = pthread_create(&avc->thread, 0, qt_player, avc);
    
    if( e == 0 )
    {
        pthread_join(avc->thread, 0);
    }

    fclose(mp4x->file);

exit:

    if( mp4x->avc1->sample_size )
    {
        __builtin_free(mp4x->avc1->sample_size);
    }
    __builtin_free(mp4x);

    LOGV("[%s:%u] done!\n", __func__, __LINE__);
    return 0;
}
#endif // LOCAL_TEST
