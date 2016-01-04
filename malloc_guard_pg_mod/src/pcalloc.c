#include "gmem.h"

/*calloc just needs to call malloc in my implementation*/
void *calloc(size_t nmemb, size_t size)
{
  return malloc(nmemb*size);
}
