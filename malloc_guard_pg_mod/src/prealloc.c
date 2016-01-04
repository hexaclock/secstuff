#include "gmem.h"

void *realloc(void *ptr, size_t size)
{
  size_t bufsize;
  void *ret;

  if (ptr == NULL)
    return malloc(size);
  if (ptr != NULL && size == 0)
    {
      free(ptr);
      return NULL;
    }

  memcpy(&bufsize,ptr-sizeof(size_t),sizeof(size_t));

  if (size == bufsize)
    return ptr;
  ret = malloc(size);
  if (size < bufsize)
    memcpy(ret,ptr,size);
  else
    memcpy(ret,ptr,bufsize);

  free(ptr);

  return ret;
}
