#include "hmac-sha1.h"
int main(int argc, char **argv){
   b32 hash[5];
   char *msg = "hi";
   bitstr m;
   hsh h;
   
   m.d=msg;
   m.l[0]=16;
   m.l[1]=0;

   sha1(&m, &h);
   rpr(h.h);
   return 0;
}
// VERIFIER openssl dgst -sha1  <(echo -n hi)
