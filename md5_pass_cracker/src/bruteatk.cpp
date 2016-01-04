#include "lab2.h"


void bruteforce(std::string *salt, dictionary_t *uhashes, dictionary_t *solved, int passlen)
{
  char w[passlen+1];
  char done[passlen+1];
  char *md5hex;
  int i;
  int end;
  end = 0;

  /*initialize arrays*/
  for (i=0; i<passlen; ++i)
    {
      w[i] = '0';
      done[i] = 'z';
    }
  w[passlen] = '\0';
  done[passlen] = '\0';
  i = passlen-1;
  while(strcmp(w,done) != 0)
    {
      md5hex = md5hash(w + *salt);
      /* cracked a hash! */
      if ((solved->find(md5hex) == solved->end()) &&
	  (uhashes->find(md5hex) != uhashes->end()))
	{
	  std::cout<<"[+] Cracked "
		   <<uhashes->at(md5hex)<<':'
		   <<w
		   <<std::endl;
	  (*solved)[md5hex] = w;
	}
      w[passlen-1]++;
      /* increment data structure */
      if (w[passlen-1] == 'z')
	for(i=passlen-1; i>end; --i)
	  {
	    if (w[i] == 'z')
	      {
		w[i] = '0';
		if (w[i-1] < 'z')
		  w[i-1]++;
	      }
	    if (w[end] == 'z')
	      end++;
	  }
      ++gl.pwgens;
      /*i=passlen-1;*/
      /*usleep(10);
      puts(w);*/
    }
  return;
}


void bruteatk(dictionary_t *uhashes, dictionary_t *solved, 
	      std::string *salt)
{
  std::string ptxt;
  int i;
  /* try to bruteforce */
  for (i=3; i<=5; ++i)
    bruteforce(salt,uhashes,solved,i);
}
