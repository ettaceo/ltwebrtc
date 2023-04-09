// file : tsdemux.c
// date : 11/24/2017
// mpeg transport stream demuxer
// ref. ITU H.222
//
#define _GNU_SOURCE
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include "ts-demux.h"

#define ERROR_LINE  (-(__LINE__))

typedef unsigned char  u8_t;
typedef unsigned short u16_t;
typedef unsigned int   u32_t;
typedef unsigned long long u64_t;

// h.222 2.4.3.3 sync_byte
#define SYNC_BYTE 0x47

///////////////////////////////////////////////////////////////////////////////
// adopted from codebits.[ch]
// endian handling
#ifdef _MSC_VER   // visual studio
#include <windows.h>
  #if REG_DWORD == REG_DWORD_BIG_ENDIAN
    #define __ORDER_BIG_ENDIAN__  1
  #else
    #define __ORDER_LITTLE_ENDIAN__  1
  #endif
  #define __BYTE_ORDER__ 1
#endif
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  #pragma message "bit endian target"
  #error "code yet to be tested"
  #define HTON32(d) (d)
  #define NTOH32(d) (d)
#else
  //#pragma message "little endian target"
  #define NTOH16(w) ((((w)&0xff)<<8)|(((w)>>8)&0xff))
  #define HTON16(d) NTOH16(d)
  #define NTOH32(d) ((NTOH16((d)&0xffff)<<16)|NTOH16(((d)>>16)&0xffff))
  #define HTON32(d) NTOH32(d)
#endif

#define BITS_PER_BYTE 8

#define BITX_LEFTOVER(bitx) ((bitx)->count-(bitx)->depth)
#define BITX_DATA_PTR(bitx) (void*)((bitx)->pbyte+(bitx)->depth)

typedef struct bitx_t
{
    unsigned char   *pbyte;   // pointer to buffer
    unsigned int     count;   // buffer count
    unsigned int     depth;   // pointer
    union
    {
        unsigned int     dword;   // output
        unsigned char    octet[4];
    };
    unsigned short   width;
    union
    {
        unsigned short  word;     // staged
        unsigned char   byte[2];

    }   bimap;

}    bitx_t;

//
// get @bits from bitstream. return negative in error
// if @bits > 32, only the last 32-bit is saved in bitx_t::dword
//
static int   next_bits(bitx_t *bitx, unsigned int bits)
{
    unsigned int width;

    if( bits == 0 ) return 0;

    if( bits <= BITS_PER_BYTE )
    {
        // clear high byte - saves caller from clamping bits
        bitx->bimap.byte[1] = '\0';

        for( width = bits; width > 0; )
        {
            int    shift;

            if( bitx->width == 0 )
            {
                if( bitx->depth >= bitx->count ) return -1;
                bitx->width = BITS_PER_BYTE;
                // low byte
                bitx->bimap.byte[0] = bitx->pbyte[bitx->depth];
                bitx->depth += 1;
            }

            shift = (width < bitx->width ?  width : bitx->width);

            bitx->bimap.word <<= shift;

            bitx->width -= shift;
            width -= shift;
        }

        bitx->dword <<= BITS_PER_BYTE;

        bitx->dword |= bitx->bimap.byte[1]; // high byte
    }
    else
    {
        int remainder = bits;
        for(width = (remainder % BITS_PER_BYTE); remainder > 0;
            remainder -= width, width = BITS_PER_BYTE)
        {
            if( width && next_bits(bitx, width) ) return -1;
        }
    }

    return 0;
}

// if @skip < 0 then skip all
static int  bitx_skip(bitx_t *bitx, int skip)
{
    if( skip < 0 ) skip = bitx->count - bitx->depth;

    bitx->width = 0;
    bitx->depth += skip;

    return (bitx->depth <= bitx->count ? 0 : -1);
}

//
// @size must be no greater than buffer size
// return 0 if succeeded, negative if not aligned to byte boundary
//
__attribute__((unused))
static int  bitx_copy(bitx_t *bitx, void *data, int size)
{
    if( bitx->width != 0 ) return -1;

    if( bitx->depth + size > bitx->count ) return -2;

    if( size > 0 )
    {
        memcpy(data, bitx->pbyte + bitx->depth, size);

        bitx->depth += size;
    }
    return 0;
}

//
// @size may be greater than remaining data size
// return number of bytes moved, negative if not aligned
//
static int  bitx_move(bitx_t *bitx, void *data, int size)
{
    if( bitx->width != 0 ) return -1;

    if( size > 0 )
    {
        if( bitx->depth + size > bitx->count )
        {
            size = bitx->count - bitx->depth;
        }

        memcpy(data, bitx->pbyte + bitx->depth, size);

        bitx->depth += size;
    }
    return size;
}

static void bitx_init(bitx_t *bitx, unsigned char *data, int size)
{
    memset(bitx, 0, sizeof(bitx_t));
    bitx->pbyte = data;
    bitx->count = size;
}

//
// move to next marker. return zero if matched. 1 if run to end
// return negative if error. @bytes must be in network order
// this is designed to seek to next startcode in h.264
//
__attribute__((unused))
static int  seek_bytes(bitx_t *bitx, unsigned char *bytes, int mlen)
{
    int   matched = 0;
    int   dword;

    // for now limit marker to 4 bytes
    assert( mlen <= 4 );

    do
    {
        if( next_bits(bitx, 8) ) return -1;

        matched = (0 == memcmp(&dword, bytes, mlen));

    } while( ! matched );

    return (matched ? 0 : 1);
}

__attribute__((unused))
static void dump_hex(unsigned char *hex, int len)
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
// data stream callback context

typedef struct tsdmx_t
{
    bitx_t  bitx;

    u32_t   packet_id;  // tracking

    // transport packet variables
    int     transport_error_indicator;
    int     payload_unit_start_indicator;
    int     transport_priority;
    int     PID;
    int     transport_scrambling_control;
    int     adaptation_field_control;
    int     continuity_counter; // appear to be per PID

    // pat packet variables
    int     pat_pointer_field;
    int     pat_table_id;
    int     pat_section_length;
    int     transport_stream_id;
    int     pat_version_number;
    int     pat_current_next_indicator;
    int     pat_section_number;
    int     pat_last_section_number;
    int     pat_program_number;
    int     program_map_pid;

    // pmt packet variables
    int     pmt_pointer_field;
    int     pmt_table_id;
    int     pmt_section_length;
    int     pmt_version_number;
    int     pmt_current_next_indicator;
    int     pmt_section_number;
    int     pmt_last_section_number;
    int     pmt_program_number;

    int     PCR_pid;
    int     aac_pid;
    int     avc_pid;
    int     sub_title_pid;
    int     aac_continuity_counter:4;
    int     aac_enforce_continuity:3;
    int     aac_continuity_started:1;
    int     avc_continuity:4;
    int     avc_enforce_continuity:3;
    int     avc_continuity_started:1;
    int     sub_continuity:4;
    int     sub_enforce_continuity:3;
    int     sub_continuity_started:1;
    int     not_in_use:8;
    int     int_not_in_user;

    // adaptation packet
    u64_t   pcr;
    u64_t   opcr;

    u8_t    pid_bitmap[1024];   // truncate 13-bit pid indicator

    // pes packet variables
    int     pes_stream_id;
    int     pes_packet_length;
    int     pes_flags;
    int     pes_header_data_length;
    u64_t   pes_pts; // present in ivy streams
    u64_t   pes_dts; // may not present

    int     tsdmx_user[0];  // marker private block boundary

    // dvb subtitle
    cbx_t   txt_cbx;
    // aac adts
    cbx_t   aac_cbx;
    // video h264/avc
    cbx_t   avc_cbx;

}  tsdmx_t;

// [12/14/2020] Table 2-6 H.222 (03/2017)
// may need to update @flag processing
static int ts_adaptation(tsdmx_t *ctx)
{
    bitx_t *bitx = &ctx->bitx;

    next_bits(bitx, 8); //
    int field_length = bitx->octet[0];

    next_bits(bitx, 8); //
    int flags = bitx->octet[0];
    field_length -= 1;

    if( flags & (1<<4) ) // PCR_flag
    {
        // PCR = PCR_base × 300 + PCR_ext
        next_bits(bitx, 32);
        ctx->pcr = bitx->dword;
        next_bits(bitx, 1);
        ctx->pcr <<= 1;
        ctx->pcr |= (bitx->dword & 0x01);
        ctx->pcr *= 300;
        next_bits(bitx, 15);
        ctx->pcr += (bitx->dword & 0x01ff);  // 9-bit

        field_length -= 6;
    }

    if( flags & (1<<3) ) // OPCR_flag
    {
        // OPCR = OPCR_base × 300 + OPCR_ext
        next_bits(bitx, 32);
        ctx->opcr = bitx->dword;
        next_bits(bitx, 1);
        ctx->opcr <<= 1;
        ctx->opcr |= (bitx->dword & 0x01);
        ctx->opcr *= 300;
        next_bits(bitx, 15);
        ctx->opcr += (bitx->dword & 0x01ff);  // 9-bit
        field_length -= 6;
    }

    // ignore the rest of field
    return bitx_skip(bitx, field_length);
}

//
// ref. h.222 2.4.4.3 Program association Table
//
static int  pat_packet(tsdmx_t *ctx)
{
    bitx_t *bitx = &ctx->bitx;

    if( ctx->payload_unit_start_indicator )
    {
        // h.222 2.4.4.2 pointer_field
        next_bits(bitx, 8);
        ctx->pat_pointer_field = bitx->octet[0];
        if( bitx_skip(bitx, ctx->pat_pointer_field) ) return ERROR_LINE;
    }

    // table id
    next_bits(bitx, 8);
    ctx->pat_table_id = bitx->octet[0];

    // reserved
    next_bits(bitx, 4);
    // as per h.222 2.1.46: all reserved bits should be set to 1

    next_bits(bitx, 12);
    int section_length = (bitx->dword & 0x0fff);
    ctx->pat_section_length = section_length;
    if( section_length > 1021 ) return ERROR_LINE; // h.222 2.4.4.5

    // ignore if pmt pid is known
    if(ctx->program_map_pid != 0 )
    {
        return bitx_skip(bitx, section_length) ? ERROR_LINE : 0;
    }

    // transport_stream_id
    next_bits(bitx, 16);
    ctx->transport_stream_id = (bitx->dword & 0xffff);
    section_length -= 2;

    // version_number
    next_bits(bitx, 8);
    ctx->pat_version_number = ((bitx->dword & 0x3e) >> 1); // 5-bit
    ctx->pat_current_next_indicator = (bitx->dword & 0x01); // 1-bit
    section_length -= 1;

    // section_number
    next_bits(bitx, 8);
    ctx->pat_section_number = bitx->octet[0];
    section_length -= 1;

    // last_section_number
    next_bits(bitx, 8);
    ctx->pat_last_section_number = bitx->octet[0];
    section_length -= 1;
    int j;
    for(j= 0; section_length > 4; j++, section_length -= 4)
    {
        if( j > 0 ) return ERROR_LINE;  // handle one program only
        // program_number
        next_bits(bitx, 16);
        ctx->pat_program_number = (bitx->dword & 0xffff);
        // program_map_pid
        next_bits(bitx, 16);
        ctx->program_map_pid = (bitx->dword & 0x1fff);
    }

    // ignore CRC32
    return bitx_skip(bitx, 4) ? ERROR_LINE : 0;
}

//
// ref. h.222 2.4.4.8 Program Map Table
//
static int  pmt_packet(tsdmx_t *ctx)
{
    bitx_t *bitx = &ctx->bitx;

    if( ctx->payload_unit_start_indicator )
    {
        // h.222 2.4.4.2 pointer_field
        next_bits(bitx, 8);
        ctx->pmt_pointer_field = bitx->octet[0];
        if( bitx_skip(bitx, ctx->pmt_pointer_field) ) return ERROR_LINE;
    }

    next_bits(bitx, 8);
    ctx->pmt_table_id = bitx->octet[0];

    // as per h.222 2.1.46: all reserved bits should be set to 1
    next_bits(bitx, 4); // expect 1011b = 0x0b

    // section length
    next_bits(bitx, 12);
    int section_length = (bitx->dword & 0x0fff);
    ctx->pmt_section_length = section_length;

    if( section_length > 1021 ) return ERROR_LINE; // h.222 2.4.4.9

    // ignore if pcr pid is known
    if(ctx->PCR_pid != 0 )
    {
        return bitx_skip(bitx, section_length) ? ERROR_LINE : 0;
    }

    // program number
    next_bits(bitx, 16);
    ctx->pmt_program_number = (bitx->dword & 0xffff);
    section_length -= 2;

    // version_number, current_next_indicator
    next_bits(bitx, 8);
    ctx->pmt_version_number = ((bitx->dword&0x3e)>>1); // 5-bit
    ctx->pmt_current_next_indicator = (bitx->dword&0x01); // 1-bit
    section_length -= 1;

    // section_number
    next_bits(bitx, 8);
    ctx->pmt_section_number = bitx->octet[0];
    section_length -= 1;

    // last_section_number
    next_bits(bitx, 8);
    ctx->pmt_last_section_number = bitx->octet[0];
    section_length -= 1;

    next_bits(bitx, 16);
    ctx->PCR_pid = (bitx->dword & 0x1fff);
    section_length -= 2;

    // program_info_length
    next_bits(bitx, 16);
    int program_info_length = (bitx->dword & 0x0fff);
    section_length -= 2;

    bitx_skip(bitx, program_info_length);

    section_length -= program_info_length;

    if( section_length < 0 ) return ERROR_LINE;

    int stream_type;
    int pid;
    int info_length;
    for(; section_length > 4; section_length -= 5+info_length )
    {
        next_bits(bitx, 8);  // stream_type
        stream_type = bitx->octet[0];
        next_bits(bitx, 16); // pid
        pid = (bitx->dword & 0x1fff);
        next_bits(bitx, 16); // info_length
        info_length = (bitx->dword & 0x0fff);

        // ref. h.222 2.4.4.9 and Table 2-34 Stream type assignments
        // assume at most one video, one audio, one subtitle
        switch(stream_type)
        {
        case 15: // aac adts
            ctx->aac_pid = pid; break;
        case 27: // avc video
            ctx->avc_pid = pid; break;
        case 6:  // private stream 1 DVB subtitle
            ctx->sub_title_pid = pid; break;
        default:
            break;
        }

        int descriptor_tag;
        int descriptor_length=0;
        int j;
        for(j=info_length; j > 0; j -= 2 + descriptor_length)
        {
            next_bits(bitx, 8);
            descriptor_tag = bitx->octet[0];
            if( descriptor_tag ){}
            next_bits(bitx, 8);
            descriptor_length = bitx->octet[0];

            if( bitx_skip(bitx, descriptor_length) ) break;
        }
    }
    if( section_length != 4 ) return ERROR_LINE;

    return bitx_skip(bitx, 4) ? ERROR_LINE : 0; // CRC32
}

static int  pes_user_data(tsdmx_t *dmx, cbx_t *cbx)
{
    bitx_t *bitx = &(dmx->bitx);
    int     e=0;

    if( cbx == 0 || cbx->call == 0 )
    {
        // discard avc data
        return bitx_skip(bitx, -1) ? ERROR_LINE : 0;
    }

    if( dmx->payload_unit_start_indicator )
    {
        if( dmx->pes_pts != 0 ) cbx->pts = dmx->pes_pts;

        cbx->work = dmx->pes_packet_length; // always zero
    }

    // for video data
    if( cbx->work == 0 ) cbx->work = BITX_LEFTOVER(bitx);

    // check for buffer overflow
    if( cbx->size > 0 && cbx->tail + cbx->work > cbx->size )
    {
        return ERROR_LINE;
    }

    if( cbx->size > 0 )
    {
        e = bitx_move(bitx, cbx->data + cbx->tail, cbx->work);

        if( e < 0 ) return ERROR_LINE;

        cbx->tail += e;
        cbx->work -= e;

        if( cbx->work < 0 ) return ERROR_LINE;
    }
    else
    {
        // null data buffer
        cbx->data = BITX_DATA_PTR(bitx);
        cbx->tail = cbx->work;
        bitx_skip(bitx, -1); // consume all
        cbx->work = 0;
    }

    e = 0;

    if( cbx->work == 0  && cbx->tail > 0 )
    {
        // caller is responsible to reset cbx->tail
        if( cbx->call ) e = cbx->call(cbx);
    }

    return e;
}

//
// ref. ETSI EN 300 743 sec 7
//
static int  dvb_sub_title(tsdmx_t *ctx)
{
    bitx_t *bitx = &(ctx->bitx);
    int     e = 0;

    next_bits(bitx, 8);
    int data_identifier = bitx->octet[0];
    if( data_identifier != 0x20 ) return ERROR_LINE;

    next_bits(bitx, 8);
    int subtitle_stream_id = bitx->octet[0];
    if( subtitle_stream_id != 0 ) return ERROR_LINE;

    // sec 7.2
    while( next_bits(bitx, 8)==0 && bitx->octet[0] == 0x0f )
    {
        // segment_type
        if( next_bits(bitx, 8) ) { e = ERROR_LINE; break; }
        int segment_type = bitx->octet[0];

        // page id
        if( next_bits(bitx, 16) ) { e = ERROR_LINE; break; }

        // segment_length
        if( next_bits(bitx, 16) ) { e = ERROR_LINE; break; }
        int segment_length = bitx->dword & 0xffff;

        if( segment_type == 0x13 ) //object data segment
        {
            // sec 7.2.5
            // object id
            if( next_bits(bitx, 16) ) { e = ERROR_LINE; break; }
            segment_length  -= 2;

            if( next_bits(bitx, 8) ) { e = ERROR_LINE; break; }
            segment_length  -= 1;

            int object_coding_method = (bitx->dword & 0x0c)>>2;

            if( object_coding_method == 0x01 )
            {
                // string object

                if( next_bits(bitx, 8) ) { e = ERROR_LINE; break; }

                segment_length  -= 1;

                // number of code
                int number_of_code = bitx->octet[0];

                if( 2 * number_of_code > segment_length )
                {
                    e = ERROR_LINE; break;
                }

                // set to text size to copy
                ctx->pes_packet_length = 2 * number_of_code;

                if( pes_user_data(ctx, &(ctx->txt_cbx)) )
                {
                    e = ERROR_LINE; break;
                }

                segment_length -= 2 * number_of_code;
            }
        }

        if( segment_length > 0 )
        {
            // ignore
            if( bitx_skip(bitx, segment_length)) { e = ERROR_LINE; break; }
        }
    }

    return e;
}

//
// ref. h.222 2.4.3.7 Semantic definition of fields in PES packet
//
static int  pes_packet(tsdmx_t *ctx)
{
    bitx_t *bitx = &(ctx->bitx);
    int e=0;
    
    // clear
    //ctx->pes_packet_length = 0; // for video, pes_packet_length is 0 
    ctx->pes_pts = 0LL;

    if( ctx->payload_unit_start_indicator )
    {
        // packet_start_code_prefix
        next_bits(bitx, 24);

        if( (bitx->dword & 0x00ffffff) != 0x01 ) return ERROR_LINE;

        // stream_id
        next_bits(bitx, 8);
        ctx->pes_stream_id = bitx->octet[0];

        // packet_length; zero for video
        next_bits(bitx, 16);
        ctx->pes_packet_length = (bitx->dword & 0x0000ffff);

        // flags
        next_bits(bitx, 16);
        ctx->pes_flags = (bitx->dword & 0x0000ffff);

        if (ctx->pes_packet_length > 0) ctx->pes_packet_length -= 2;

        // header_data_length
        next_bits(bitx, 8);
        ctx->pes_header_data_length = bitx->octet[0];

        if (ctx->pes_packet_length > 0)
        {
            ctx->pes_packet_length -= 1;  // pes_header_data_length
            ctx->pes_packet_length -= ctx->pes_header_data_length;
        }
        if( ctx->pes_packet_length < 0 ) return ERROR_LINE;

        if( ctx->pes_flags & 0x80 ) // PTS_DTS_flags=10b
        {
            ctx->pes_header_data_length -= 5;

            if( ctx->pes_header_data_length < 0 ) return ERROR_LINE;

            ctx->pes_pts = 0;
            next_bits(bitx, 8);  //
            ctx->pes_pts |= ((bitx->dword & 0x000e) >> 1); // 3-bit
            next_bits(bitx, 16);
            ctx->pes_pts <<= 15;
            ctx->pes_pts |= ((bitx->dword & 0xfffe) >> 1); // 15-bit
            next_bits(bitx, 16);
            ctx->pes_pts <<= 15;
            ctx->pes_pts |= ((bitx->dword & 0xfffe) >> 1); // 15-bit
        }
        // ignore the rest of header
        if (bitx_skip(bitx, ctx->pes_header_data_length)) return ERROR_LINE;
    }

    if( ctx->PID == ctx->sub_title_pid)
    {
        // dvb subtitle
        e = dvb_sub_title(ctx);
    }
    else if( ctx->PID == ctx->avc_pid )
    {
        // avc data
        e = pes_user_data(ctx, &(ctx->avc_cbx));
    }
    else if( ctx->PID == ctx->aac_pid)
    {
        // aac data
        e = pes_user_data(ctx, &(ctx->aac_cbx));
    }
    else
    {
        // ignore unknown pid
        bitx_init(bitx, 0, 0);
    }

    return e;
}

//
// ref. h.222 2.4.3.2 Transport Stream packet layer
//
static int  transport_packet(tsdmx_t *ctx)
{
    bitx_t *bitx = &(ctx->bitx);
    int     e=0;

    next_bits(bitx, 8);
    if( bitx->octet[0] != SYNC_BYTE ) return ERROR_LINE;

    next_bits(bitx, 16);

    // transport_error_indicator
    if( bitx->dword & 0x8000 ) return ERROR_LINE;
    // payload_unit_start_indicator
    ctx->payload_unit_start_indicator = ((bitx->dword & 0x4000) >> 14);

    int pid = (bitx->dword & 0x1fff);
    ctx->pid_bitmap[pid/8] |= (1<<(pid%8));
    ctx->PID = pid;

    next_bits(bitx, 8);
    // transport_scrambling_control
    ctx->transport_scrambling_control = ((bitx->dword & 0xc0) >> 6);
    // adaptation_field_control
    ctx->adaptation_field_control = ((bitx->dword & 0x30) >> 4);
    // continuity_counter
    ctx->continuity_counter = (bitx->dword & 0x0f);

    if( ctx->adaptation_field_control & 0x02 )
    {
        // parse adaption field
        if( ts_adaptation(ctx) ) return ERROR_LINE;
    }
    if( ctx->adaptation_field_control & 0x01 )
    {
        if( pid == 0 ) // psi: pat
        {
            if( (e = pat_packet(ctx)) ) return e;
        }
        else if( pid == ctx->program_map_pid )
        {
            if( (e = pmt_packet(ctx)) ) return e;
        }
        else if( ctx->PCR_pid > 0 &&  // ignore unknown pid (vlc)
                 (pid == ctx->aac_pid || 
                  pid == ctx->avc_pid ||
                  pid == ctx->sub_title_pid) )
        {
            if( (e = pes_packet(ctx)) ) return e;
        }
        else bitx_init(bitx, 0, 0);
    }

    // must consume all data
    if( bitx->depth != bitx->count || bitx->width != 0 )
    {
        return ERROR_LINE;
    }

    return 0;
}

///////////////////////////////////////////////////////////////////////////////

void  * init_ts_demuxer(int aac_len, int avc_len, int txt_len)
{
    tsdmx_t  *dmx;
    size_t    len;

    len = sizeof(tsdmx_t);
    len += aac_len > 0 ? aac_len : 0;
    len += avc_len > 0 ? avc_len : 0;
    len += txt_len > 0 ? txt_len : 0;

    dmx = calloc(1, len );

    if( dmx )
    {
        int pnt = 0;

        if( aac_len > 0 )
        {
            dmx->aac_cbx.size = aac_len;
            dmx->aac_cbx.data = (unsigned char*)(dmx+1) + pnt;
        }

        pnt += aac_len;

        if( avc_len > 0 )
        {
            dmx->avc_cbx.size = avc_len;
            dmx->avc_cbx.data = (unsigned char*)(dmx+1) + pnt;
        }

        pnt += avc_len;

        if( txt_len > 0 )
        {
            dmx->txt_cbx.size = txt_len;
            dmx->txt_cbx.data = (unsigned char*)(dmx+1) + pnt;
        }
    }
    return dmx;
}

void    zero_ts_demuxer(void *dmx)
{
    if( dmx != 0 )
    {
        size_t len = offsetof(tsdmx_t, tsdmx_user);

        memset(dmx, 0, len);

        ((tsdmx_t*)dmx)->txt_cbx.tail = 0;
        ((tsdmx_t*)dmx)->avc_cbx.tail = 0;
        ((tsdmx_t*)dmx)->aac_cbx.tail = 0;
    }
}

void    free_ts_demuxer(void *dmx)
{
    if( dmx) free(dmx);
}

cbx_t * get_demuxer_cbx(void *dmx, e_pes_type type)
{
    tsdmx_t  *ctx = dmx;

    if( ctx == 0 ) return 0;

    switch(type)
    {
    case e_aac: return &(ctx->aac_cbx);
    case e_avc: return &(ctx->avc_cbx);
    case e_txt: return &(ctx->txt_cbx);
    default: break;
    }

    return 0;
}

int    pes_information(void *dmx, pes_t *pes)
{
    tsdmx_t  *ctx = dmx;

    if( 0 == pes) return -2;

    memset(pes, 0, sizeof(pes_t));

    pes->type = e_max;

    if( ctx->program_map_pid == 0 ) return -1; // not ready

    pes->pid = ctx->PID;

    if( ctx->PID == 0)
    {
        pes->type = e_pat;
    }
    else if( ctx->PID == ctx->program_map_pid )
    {
        pes->type = e_pmt;
    }
    else if( ctx->PID == ctx->aac_pid )
    {
        pes->type = e_aac;
    }
    else if( ctx->PID == ctx->avc_pid )
    {
        pes->type = e_avc;
    }
    else if( ctx->PID == ctx->sub_title_pid )
    {
        pes->type = e_txt;
    }

    pes->pts = ctx->pes_pts;
    pes->pcr = ctx->pcr;
    
    return 0;
}

int    is_pes_boundary(void *dmx, e_pes_type type)
{
    tsdmx_t  *ctx = dmx;

    int pid = 0;

    switch( type )
    {
    case e_pat:
        break;
    case e_pmt:
        pid = ctx->program_map_pid;
        break;
    case e_aac:
        pid = ctx->aac_pid;
        break;
    case e_avc:
        pid = ctx->avc_pid;
        break;
    case e_txt:
        pid = ctx->sub_title_pid;
        break;
    default:
        break;
    }
    if( (pid == 0) && (type != e_pat) )
    {
        return -1; // not ready
    }
    if( pid != ctx->PID )
    {
        return 0;
    }
    
    return ctx->payload_unit_start_indicator;
}

//
// return negative in error
//
int     feed_ts_demuxer(void *dmx, void *pkt, int len)
{
    tsdmx_t *ctx = dmx;
    unsigned char *tsp = 0;
    int      e = 0;

    for(tsp = pkt; len >= TS_PKT_SIZE; len -= TS_PKT_SIZE)
    {
        bitx_init(&(ctx->bitx), tsp, TS_PKT_SIZE);
        if( (e = transport_packet(ctx)) ) break;
        tsp += TS_PKT_SIZE;
        ctx->packet_id += 1;
    }

    return e;
}

///////////////////////////////////////////////////////////////////////////////

#if defined(FILE_READER) || defined(RTSP_CLIENT) || defined(MSDB_CLIENT)

static int aac_total, avc_total, txt_total;
int aac_data(cbx_t *cbx)
{
    aac_total += cbx->tail;
    if( cbx->user ) fwrite(cbx->data, 1, cbx->tail, cbx->user);
    cbx->tail = 0;

    return 0;
}

int avc_data(cbx_t *cbx)
{
    // ISO 14496-10 Annex B suggests a frame delay in detecting end-of-frame
    static char *startcode="\x00\x00\x00\x01";

    avc_total += (cbx->tail - cbx->mark); // fresh data

    if( cbx->mark && memcmp(cbx->data + cbx->mark, startcode, 4) == 0 )
    {
        if( cbx->user ) fwrite(cbx->data, 1, cbx->mark, cbx->user);

        // move last packet to head
        memmove(cbx->data, cbx->data + cbx->mark, cbx->tail - cbx->mark);

        cbx->tail -= cbx->mark;
    }
    cbx->mark = cbx->tail;

    return 0;
}

int sub_text(cbx_t *cbx)
{
    txt_total += cbx->tail;

    if( txt_total == cbx->tail )
    {
        char txt[24]={(0)};
        for(int k = 0; k < cbx->tail; k+=2)
        {
            txt[k/2] = cbx->data[k+1];
        }
        printf("[%s] * %s *\n", __FUNCTION__, txt);
    }
    cbx->tail = 0;

    return 0;
}

#endif // FILE_READER or RTSP_CLIENT

#ifdef FILE_READER

int main(int argc, char *argv[])
{
    FILE    *f;
    u8_t     pkt[TS_PKT_SIZE];
    tsdmx_t *dmx;
    cbx_t   *aac, *avc, *sub;
    int      e = 0;
    if(argc < 2 )
    {
        printf("Usage:\t%s <ts file>\n", argv[0]);
        return 0;
    }
    f = fopen(argv[1], "r");
    if( f == 0 )
    {
        printf(" Failed to open %s\n", argv[1]);
        return 0;
    }

    dmx = init_ts_demuxer((1<<10), (1<<20), 128);
    aac = get_demuxer_cbx(dmx, e_aac);
    aac->call = aac_data;
    avc = get_demuxer_cbx(dmx, e_avc);
    avc->call = avc_data;
    sub = get_demuxer_cbx(dmx, e_txt);
    sub->call = sub_text;

    // bbc ts muxer may be subject to discontinuity
    //dmx->enforce_continuity = 1;

    avc->user = fopen("tsdemux.h264", "w");
    aac->user = fopen("tsdemux.aac", "w");

    while( TS_PKT_SIZE == fread(pkt, 1, TS_PKT_SIZE, f) )
    {
        if( (e = feed_ts_demuxer(dmx, pkt, TS_PKT_SIZE)) ) break;
    }
    if( e )
    {
        printf("Error: e=%d\n", e);
        printf("Offset %x\n", dmx->packet_id*188);
    }
    //printf("Total packets processed: %u discontinuities=%d\n",
    //        dmx->packet_id, dmx->discontinuities);
    {
        int k;
        for(k=0; k < sizeof(dmx->pid_bitmap); k++)
        {
            int j;
            for(j=0; j < 8; j++)
            if( dmx->pid_bitmap[k] & (1<<j) ) printf(" packet id %d\n", k*8 + j);
        }
    }
    printf(" pat_program_number=%d pmt_program_number=%d program_map_pid=%d\n",
            dmx->pat_program_number, dmx->pmt_program_number,  dmx->program_map_pid);
    printf(" pcr_pid=%d aac_pid=%d avc_pid=%d txt_pid=%d\n",
            dmx->PCR_pid, dmx->aac_pid, dmx->avc_pid, dmx->sub_title_pid);
    printf(" aac_total=%d avc_total=%d txt_total=%d\n", aac_total, avc_total, txt_total);

    fclose(aac->user);
    fclose(avc->user);

    free_ts_demuxer(dmx);

    fclose(f);

    return 0;
}

#endif // FILE_READER

#if defined(RTSP_CLIENT) || defined(MSDB_CLIENT)

#include <signal.h>
#include <unistd.h>

#if defined(RTSP_CLIENT)
  #include "rtspuser.h"
#elif defined(MSDB_CLIENT)
  #include "msdbuser.h"
#endif

//
// little-endian
//
typedef struct rtp_hdr_t
{
    unsigned char cc:4;   // CSRC count
    unsigned char x:1;   // header extension glag
    unsigned char p:1;   // padding flag
    unsigned char version:2;  // 2

    unsigned char pt:7; // payload type
    unsigned char m:1;  // marker bit

    unsigned short seq;

    unsigned int ts;
    unsigned int ssrc;

}  rtp_hdr_t;

static int g_quit;

static void sig_int(int sig)
{
    g_quit = 1;
}

int sdp_tsspec(void *dmx, char *sdp, int size)
{
    g_quit = (0 == strcasestr(sdp, "rtpmap:33"));
    if( g_quit ) printf("[%s] ** NOT transport stream **\n", __FUNCTION__);
    return 0;
}
  
// return value discarded
int rtp_packet(void *dmx, void *pkt, int size)
{
    rtp_hdr_t *rtp=pkt;
    int e = 0;

    if( g_quit ) return 0;
    
    pkt = (void*)((char*)rtp + sizeof(rtp_hdr_t));
    size -= sizeof(rtp_hdr_t);
   
    // csrc
    pkt = ((char*)pkt + rtp->cc * 4);
    size -= rtp->cc * 4;
    // extension
    if( rtp->x )
    {
        int hlen = ((u8_t*)pkt)[2]*256 + ((u8_t*)pkt)[3];
        pkt = ((char*)pkt + (hlen + 1) * 4);
        size -= (hlen + 1) * 4;
    }
    // padding
    if( rtp->p )
    {
        u8_t plen = ((u8_t*)pkt)[size-1];
        size -= plen;
    }

    if( (e = feed_ts_demuxer(dmx, pkt, size)) )
    {
        printf("[%s:%u] ERROR e=%d\n", __FUNCTION__, __LINE__, e);
        g_quit = 2; // exit
    }

    return 0;
}

int main(int argc, char *argv[])
{
    tsdmx_t *dmx;
    cbx_t   *aac, *avc, *sub;
    void    *rtsp;

    if(argc < 2 )
    {
        printf("Usage:\t%s <full-url>\n", argv[0]);
        return 0;
    }

    signal(SIGINT, sig_int);

    dmx = init_ts_demuxer((1<<10), (1<<20), 128);
    aac = get_demuxer_cbx(dmx, e_aac);
    aac->call = aac_data;
    avc = get_demuxer_cbx(dmx, e_avc);
    avc->call = avc_data;
    sub = get_demuxer_cbx(dmx, e_txt);
    sub->call = sub_text;

    avc->user = fopen("tsdemux.h264", "w");
    aac->user = fopen("tsdemux.aac", "w");

#ifdef RTSP_CLIENT
    rtsp = start_rtsp_client(dmx, argv[1], sdp_tsspec, rtp_packet);
    while( ! g_quit ) sleep(1);
    close_rtsp_client(rtsp);
#elif defined(MSDB_CLIENT)
    rtsp = start_msdb_client(dmx, argv[1], sdp_tsspec, rtp_packet);
    while( ! g_quit ) sleep(1);
    close_msdb_client(rtsp);
#endif

    fclose(aac->user);
    fclose(avc->user);

    printf("\nTotal packets processed: %u\n", dmx->packet_id);
    {
        int k;
        for(k=0; k < sizeof(dmx->pid_bitmap); k++)
        {
            int j;
            for(j=0; j < 8; j++)
            if( dmx->pid_bitmap[k] & (1<<j) ) printf(" packet id %d\n", k*8 + j);
        }
    }
    printf(" pat_program_number=%d pmt_program_number=%d program_map_pid=%d\n",
            dmx->pat_program_number, dmx->pmt_program_number,  dmx->program_map_pid);

    printf(" pcr_pid=%d aac_pid=%d avc_pid=%d txt_pid=%d\n",
            dmx->PCR_pid, dmx->aac_pid, dmx->avc_pid, dmx->sub_title_pid);

    printf(" aac_total=%d avc_total=%d txt_total=%d\n", aac_total, avc_total, txt_total);

    free_ts_demuxer(dmx);

    return 0;
}

#endif // RTSP_CLIENT || MSDB_CLIENT

#if defined(TS_BOUNDARY)

#include <signal.h>
#include <unistd.h>

#if 1
  #include "rtspuser.h"
#else
  #include "msdbuser.h"
#endif

//
// little-endian
//
typedef struct rtp_hdr_t
{
    unsigned char cc:4;   // CSRC count
    unsigned char x:1;   // header extension glag
    unsigned char p:1;   // padding flag
    unsigned char version:2;  // 2

    unsigned char pt:7; // payload type
    unsigned char m:1;  // marker bit

    unsigned short seq;

    unsigned int ts;
    unsigned int ssrc;

}  rtp_hdr_t;

static int g_quit;

static void sig_int(int sig)
{
    g_quit = 1;
}

int sdp_tsspec(void *dmx, char *sdp, int size)
{
    g_quit = (0 == strcasestr(sdp, "rtpmap:33"));
    if( g_quit ) printf("[%s] ** NOT transport stream **\n", __FUNCTION__);
    return 0;
}
  
// return value discarded
int rtp_packet(void *dmx, void *pkt, int size)
{
    rtp_hdr_t *rtp=pkt;
    int e = 0;

    if( g_quit ) return 0;
    
    pkt = (void*)((char*)rtp + sizeof(rtp_hdr_t));
    size -= sizeof(rtp_hdr_t);
   
    // csrc
    pkt = ((char*)pkt + rtp->cc * 4);
    size -= rtp->cc * 4;
    // extension
    if( rtp->x )
    {
        int hlen = ((u8_t*)pkt)[2]*256 + ((u8_t*)pkt)[3];
        pkt = ((char*)pkt + (hlen + 1) * 4);
        size -= (hlen + 1) * 4;
    }
    // padding
    if( rtp->p )
    {
        u8_t plen = ((u8_t*)pkt)[size-1];
        size -= plen;
    }

    if( (e = feed_ts_demuxer(dmx, pkt, size)) )
    {
        printf("[%s:%u] ERROR e=%d\n", __FUNCTION__, __LINE__, e);
        g_quit = 2; // exit
    }
tsdmx_t *x=dmx;
printf("[%u] PID=%d payload_unit_start_indicator=%d  pes_pts=%lld\n",
x->packet_id, x->PID, x->payload_unit_start_indicator, x->pes_pts);
printf("[%u] new frame %d\n", x->packet_id, is_pes_boundary(x, e_pat));

    return 0;
}

int main(int argc, char *argv[])
{
    char   _blk[sizeof(tsdmx_t)]={0};
    tsdmx_t *dmx=(void*)&_blk;
    void    *rtsp;

    if(argc < 2 )
    {
        printf("Usage:\t%s <full-url>\n", argv[0]);
        return 0;
    }

    signal(SIGINT, sig_int);

#if 1
    rtsp = start_rtsp_client(dmx, argv[1], sdp_tsspec, rtp_packet);
    while( ! g_quit ) sleep(1);
    close_rtsp_client(rtsp);
#else
    rtsp = start_msdb_client(dmx, argv[1], sdp_tsspec, rtp_packet);
    while( ! g_quit ) sleep(1);
    close_msdb_client(rtsp);
#endif

    printf("\nTotal packets processed: %u\n", dmx->packet_id);
    {
        int k;
        for(k=0; k < sizeof(dmx->pid_bitmap); k++)
        {
            int j;
            for(j=0; j < 8; j++)
            if( dmx->pid_bitmap[k] & (1<<j) ) printf(" packet id %d\n", k*8 + j);
        }
    }
    printf(" pat_program_number=%d pmt_program_number=%d program_map_pid=%d\n",
            dmx->pat_program_number, dmx->pmt_program_number,  dmx->program_map_pid);

    printf(" pcr_pid=%d aac_pid=%d avc_pid=%d txt_pid=%d\n",
            dmx->PCR_pid, dmx->aac_pid, dmx->avc_pid, dmx->sub_title_pid);

    return 0;
}


#endif // TS_BOUNDARY
///////////////////////////////////////////////////////////////////////////////
