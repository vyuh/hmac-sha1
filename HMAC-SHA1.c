#include "hmac-sha1.h"
int main(int argc, char **argv){
   b32 hash[5];
   char *msg = "hi";
   bitstr m;
   
   m.d=msg;
   m.l[0]=16;
   m.l[1]=0;

   hmac_sha1(&m, &m, hash);
   rpr(hash);
   return 0;
}
// int hmac_sha1(bitstr *key, bitstr *msg, unsigned mac[5]){
// VERIFIER openssl dgst -sha1 -hmac hi  <(echo -n hi)
