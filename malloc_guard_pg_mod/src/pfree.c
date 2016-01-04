#include "gmem.h"

void free(void *ptr)
{
  int pgsz;
  int padlen;
  size_t bufsize;

  if (ptr == NULL)
    return;

  pgsz = getpagesize();
  memcpy(&bufsize,ptr-sizeof(size_t),sizeof(size_t));

  padlen = (pgsz - (bufsize % pgsz));
  if (munmap(ptr-padlen,padlen+bufsize))
    perror(strerror(errno));

  if (!mprotect(ptr+bufsize,pgsz,PROT_READ|PROT_WRITE))
    {
      if (munmap(ptr+bufsize,pgsz))
	perror(strerror(errno));
    }
  else
    perror(strerror(errno));
}
