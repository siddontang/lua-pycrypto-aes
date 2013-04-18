#ifndef _LUA_PYCRYPTO_AES_
#define _LUA_PYCRYPTO_AES_

#define BLOCK_SIZE 16
#define KEY_SIZE 0

#define MAXKC   (256/32)
#define MAXKB   (256/8)
#define MAXNR   14

typedef unsigned char   u8; 
typedef unsigned short  u16;    
typedef unsigned int    u32;

typedef struct {
    u32 ek[ 4*(MAXNR+1) ]; 
    u32 dk[ 4*(MAXNR+1) ];
    int rounds;
} block_state;

int block_init(block_state *state, unsigned char *key, int keylen);
void block_encrypt(block_state *self, u8 *in, u8 *out);
void block_decrypt(block_state *self, u8 *in, u8 *out);

#endif
