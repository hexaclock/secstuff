#ifndef _GMEM_H_
#define _GMEM_H_

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/types.h>

/*libc/original functions*/
void *(*real_malloc)(size_t);
void  (*real_free)(void*);
void *(*real_calloc)(size_t,size_t);
void *(*real_realloc)(void*,size_t);
void *(*real_memalign)(size_t,size_t);


/*override functions with guard page*/
void *malloc(size_t size);
void free(void *ptr);
void *calloc(size_t nmemb, size_t size);
void *realloc(void *ptr, size_t size);
void *memalign(size_t alignment, size_t size);

#endif
