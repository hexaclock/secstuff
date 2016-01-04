#include "lab2.h"

char *md5hash(std::string str)
{
  unsigned char dgst[MD5_DIGEST_LENGTH];
  const char *preimage;
  char *md5hexret;
  int i;
  md5hexret = (char *)malloc((2*MD5_DIGEST_LENGTH)+1);
  preimage = str.c_str();

  MD5((unsigned char*)preimage, strlen(preimage),
      (unsigned char*)&dgst);
  for (i=0; i<16; ++i)
    sprintf(&md5hexret[i*2], "%02x", (unsigned int)dgst[i]);

  return md5hexret;
}
