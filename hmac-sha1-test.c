#include "hmac-sha1.c"
int main (int argc, char **argv) {
  b32 hash[5];
  char *msg = "hi";
  char *key = "hi";
  bitstr m;
  bitstr k;

  if (argc>1) {
    msg = argv[1];
    key = argv[1];
  }
  if (argc>2) {
    key = argv[2];
  }

  m.d = msg;
  m.l[0] = 8*strlen(msg);
  m.l[1] = 0;

  k.d = key;
  k.l[0] = 8*strlen(key);
  k.l[1] = 0;

  hmac_sha1 (&k, &m, hash);
  rpr (hash);
  return 0;
}

/*  int hmac_sha1(bitstr *key, bitstr *msg, unsigned mac[5]){ */
/*  VERIFIER openssl dgst -sha1 -hmac hi  <(echo -n hi) */
