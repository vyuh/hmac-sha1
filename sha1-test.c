#include "hmac-sha1.c"
int main (int argc, char **argv) {
  b32 hash[5];
  char *msg = "hi";
  bitstr m;
  hsh h;
  if (argc>1) {
    msg = argv[1];
  }

  m.d = msg;
  m.l[0] = 8*strlen(msg);
  m.l[1] = 0;

  sha1 (&m, &h);
  rpr (h.h);
  return 0;
}

/*  VERIFIER openssl dgst -sha1  <(echo -n hi) */
