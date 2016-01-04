#include "gmem.h"

void *memalign(size_t alignment, size_t size)
{
  int pgsz;
  /*int xpad;*/
  size_t rmdr;
  size_t align;
  void *ret;
  void *buf;
  void *guardpg;

  if (size == 0 || alignment <= 1)
    return NULL;
  /*probably 4KB*/
  pgsz = getpagesize();
  /*should be either 4B or 8B (32bit or 64bit)*/
  /*xpad = sizeof(void *);*/
  /*make sure we have enough space for metadata*/
  size += (size_t)sizeof(size_t);
  /*align pointer to alignment*/
  if ( (rmdr = size % alignment) != 0 )
    size = size + alignment - rmdr;
  align = size;

  if ( (rmdr = size % pgsz) != 0 )
    align = size + pgsz - rmdr;
  /*MAP_ANONYMOUS automatically initializes to 0*/
  guardpg = mmap(NULL, pgsz, PROT_NONE, MAP_ANONYMOUS|MAP_SHARED, -1, 0);
  if (guardpg == MAP_FAILED)
    {
      puts("failed to mmap guardpg");
      return (void*)0;
    }

  buf = mmap(guardpg-pgsz, align, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_SHARED, -1, 0);
  if (buf == MAP_FAILED)
    {
      puts("failed to malloc buf");
      puts(strerror(errno));
      return (void*)0;
    }
  /*printf("Pad/buf start: %p\n",buf);*/
  /*printf("End of buf/pad region: %p\n",buf+align);*/

  /*store metadata for pfree()*/
  ret = buf+align-size+sizeof(size_t);
  size = size - (size_t)sizeof(size_t);
  memcpy(ret-sizeof(size_t),&size,sizeof(size_t));
  /*[---PAD---]|^[buffer][guardpg]*/
  return ret;
}
