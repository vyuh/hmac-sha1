typedef struct {
    unsigned char *d;
    unsigned l;
} bitstr;

#include <string.h>

b8 *wr32be(b32 n, b8 *msg) {
    b32 mask = 0xff;
    *msg = n >> 24; ++msg;
    *msg = (n >> 16) & mask; ++msg;
    *msg = (n >> 8) & mask; ++msg;
    *msg = n & mask;  return ++msg;
} //libpk

int hmac_sha1(bitstr *key, bitstr *msg, unsigned *code){
    unsigned k[16] = { 0 };
    unsigned o[16], i[16];
    unsigned x;
    bitstr fin;


    if(key->l > 512) {
        sha1(key->d, key->l, k); 
        for(x=0; x<5; x++) wr32be(k[i], k+i); //FIXME: if wr32be works not
    } else memcpy(k, key->d, key->l/8 + 1);

    for(x=0;x<16; x++) {
        o[x]=0x5c5c5c5c ^ k[x];
        i[x]=0x36363636 ^ k[x];
    }

    fin.l[1]=msg->l[1];
    fin.l[0]=msg->l[0]+ //TODO a good way to handle large msgs 
    fin.d = malloc(
    
