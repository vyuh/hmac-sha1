typedef unsigned char b8;
typedef unsigned b32;
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
int rpr(b32 *h) {
    printf("%08x%08x%08x%08x%08x\n", *h, *(h+1),*(h+2), *(h+3), *(h+4));
    return 0;
}

int die(char *msg) {
    fputs( msg, stderr);
    exit(0);
} //libpk

b8 *wr32be(b32 n, b8 *msg) {
    b32 mask = 0xff;
    *msg = n >> 24; ++msg;
    *msg = (n >> 16) & mask; ++msg;
    *msg = (n >> 8) & mask; ++msg;
    *msg = n & mask;  return ++msg;
} //unused libpk

b8 *rd32be(b32 *n, b8 *msg) {
    *n = *msg << 24; ++msg;
    *n |= *msg << 16; ++msg;
    *n |= *msg << 8; ++msg;
    *n |= *msg;  return ++msg;
} //libpk

int sha1(b8 * msg, b32 n_bits[2], b32 hash[5]) {
    b32 a[5];
    b32 h[5]={ 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0};
    b32 w[80];
    b32 left[2];
    int i, j, b;

    left[0]=n_bits[0];
    left[1]=n_bits[1];

    while(left[1]||(left[0]>512)) {
        for(i=0; i<16; i++) msg=rd32be(w+i,msg);
        grind(w,a,h);
        left[0]-=512;
        if (left[0]>512){
            left[1]--;
	    if (left[1]>1) die("underflow\n");
        }
    }

    j=left[0]/32; b=left[0];
    for(i=0; i<j; i++) msg=rd32be(w+i,msg);
    left[0]-=j*32;
    w[i]= 1 << (31 - left[0]);
    if (b > 0) { w[i] |= *msg << 24; ++msg; b-=8;}
    if (b > 0) { w[i] |= *msg << 16; ++msg; b-=8;}
    if (b > 0) { w[i] |= *msg << 8; ++msg; b-=8;}
    if (b > 0) { w[i] |= *msg; ++msg; b-=8;}
    w[i]&= 0xffffffff << (31 - left[0]); i++;
    if(j>=14) {
        if(i==15) w[15]=0;
        grind(w,a,h);
        i=0;
    }
    for(;i<14;i++) w[i]=0;
    w[i]=n_bits[1]; i++;
    w[i]=n_bits[0];
    grind(w,a,h);
    for(i=0; i<5; i++) hash[i]=h[i];
    return 0;

}

b32 f(b32 t, b32 *a, b32 *w){
    b32 temp=0;
    b32 k[4]={ 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6};
    temp = ((a[0] << 5) | (a[0] >> 27)) + a[4] + w[t];
    switch(t/20){
        case 0:
	    temp+=k[0];
	    temp+=(a[1]&a[2])|((~a[1])&a[3]);
	    break;
	case 1:
	    temp+=k[1];
	    temp+=a[1]^a[2]^a[3];
	    break;
	case 2:
	    temp+=k[2];
	    temp+=(a[1]&a[2])|(a[1]&a[3])|(a[2]&a[3]);
	    break;
	case 3:
	    temp+=k[3];
	    temp+=a[1]^a[2]^a[3];
	    break;
    }
    return temp;
}

int grind(b32 *w, b32 *a, b32 *h){
    b32 t, temp;
    for(t=16; t<80; t++) {
        temp = w[t-3]^w[t-8]^w[t-14]^w[t-16];
        w[t] = (temp << 1) | (temp >> 31);
    }
    for(t=0; t<5; t++) a[t]=h[t];
    for(t=0; t<80; t++) {
        temp = f(t, a, w);
        a[4] = a[3];
        a[3] = a[2];
        a[2] = (a[1] << 30) | (a[1] >> 2) ;
        a[1] = a[0];
        a[0] = temp;
    }
    for(t=0; t<5; t++ )  h[t]+=a[t];
    return 0;
}



int main(int argc, char **argv){
   b32 l[2];
   b32 hash[5];
   l[0]=16;
   l[1]=0;
   sha1("hi", l, hash);
   rpr(hash);
   return 0;
}
/* rfc3174 
it all boiled down to reading big endian numbers correctly ;)
and realizing the you are not writing anything in big endian form :P

Wed Jul 16 00:32:21 IST 2014
*/
