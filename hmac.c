//TODO #include "sha1.h"
#include <string.h>

b8 *wr32be(b32 n, b8 *msg) {
    b32 mask = 0xff;
    *msg = n >> 24; ++msg;
    *msg = (n >> 16) & mask; ++msg;
    *msg = (n >> 8) & mask; ++msg;
    *msg = n & mask;  return ++msg;
} //libpk

int hmac_sha1(bitstr *key, bitstr *msg, unsigned mac[5]){
    unsigned k[16] = { 0 };
    unsigned o[16], i[16];
    unsigned x;
    hsh h, fin;


    if(key->l[1]||key->l[0] > 512) {
        sha1(key, &h); 
        for(x=0; x<5; x++) wr32be(h.h[x], k+x); //FIXME: if wr32be works not
    } else memcpy(k, key->d, key->l[0]/8 + (key->l[0]%8 && 1));

    for(x=0;x<16; x++) {
        o[x]=0x5c5c5c5c ^ k[x];
        i[x]=0x36363636 ^ k[x];
    }

    
    hsh_rst(&h);
    sha1_nxt(i, 512, &h);
    sha1_finish(msg, &h);
    for(x=0; x<5; x++) wr32be(h.h[x], h.h+x); //FIXME: if wr32be works not
    hsh_rst(&fin);
    sha1_nxt(o, 512, &fin);
    sha1_end(h.h, 160, &fin);
 
    for(x=0; x<5; x++) mac[x]=fin.h[x];
    return 0;

}
        
