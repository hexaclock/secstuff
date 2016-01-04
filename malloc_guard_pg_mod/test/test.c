#include "lab5.h"

int main(int argc, char **argv)
{
  char *s,*x,*y;

  s = (char *)malloc(15*sizeof(char));
  x = (char *)malloc(8*sizeof(char));
  y = (char *)calloc(64,sizeof(char));

  if (s == NULL)
    {
      puts("malloc failed");
      return -1;
    }
  strncpy(s,"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",15);
  strcpy(x,"ABCDEFG");
  strcpy(y,"hihihihihi");
  /*for (i=0; i<2000; ++i)
    if (s[i] != 0)
    puts("i does not equal 0");*/
  
  x = realloc(x,16);
  strcat(x,"HIJKLMNO");
  printf("s: %s\n",s);
  printf("x: %s\n",x);
  printf("y: %s\n",y);

  free(s);
  free(x);
  free(y);

  /*a = (char *)memalign(7,(16*sizeof(char)));
  printf("%p\n",a);
  strncpy(a,"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",10);
  free(a);*/


  return 0;
}
