typedef struct {
    unsigned char *d;
    unsigned type;
    unsigned l[2];
} str;

#include <string.h>

b8 *wr32be(b32 n, b8 *msg) {
    b32 mask = 0xff;
    *msg = n >> 24; ++msg;
    *msg = (n >> 16) & mask; ++msg;
    *msg = (n >> 8) & mask; ++msg;
    *msg = n & mask;  return ++msg;
} //libpk

int hmac_sha1(str *key, str *msg, unsigned *code){
    unsigned k[16] = { 0 };
    unsigned o[16], i[16];
    unsigned x;
    str fin;


    if(((key->l[1]||key->l[0] > 64))) {
        sha1(key->d, key->l , k); // FIXME: key->l = nbyte. sha1 expects nbits
        for(x=0; x<5; x++) wr32be(k[i], k+i); //FIXME: if wr32be works not
    }
    else memcpy(k, key->d, key->l[0]);

    for(x=0;x<16; x++) {
        o[x]=0x5c5c5c5c ^ k[x];
        i[x]=0x36363636 ^ k[x];
    }

    fin.l[1]=msg->l[1];
    fin.l[0]=msg->l[0]+
    fin.d = malloc(
    
