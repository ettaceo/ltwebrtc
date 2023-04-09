//
// adopted from http://bradconte.com/rc4_c
//
#ifndef RC4_H_
#define RC4_H_

#define RC4K(key, key_len, plain, plain_len, encrypted) \
    rc4k((key),(key_len),(plain),(plain_len),(encrypted))

#define RC4INIT(ctx, key, key_len) \
    rc4init(ctx, (key), (key_len))

#define RC4H(ctx, data, data_len, result) \
    rc4h(ctx, (data), (data_len), (result))

typedef struct rc4cx_t
{
    unsigned char state[256];

}    rc4cx_t;

#ifdef __cplusplus
extern "C" {
#endif

void ksa(unsigned char state[256], unsigned char key[], int len);
void prga(unsigned char state[], unsigned char out[], int len);
void rc4k(unsigned char *key, int key_len, const unsigned char *data, int data_len, unsigned char *result);

void rc4init(rc4cx_t *ctx, unsigned char *key, int key_len);
void rc4h(rc4cx_t *ctx, const unsigned char *data, int data_len, unsigned char *result);


#ifdef __cplusplus
}
#endif

#endif // RC4_H_
