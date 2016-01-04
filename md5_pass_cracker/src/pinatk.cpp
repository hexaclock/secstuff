#include "lab2.h"

void pinatk(dictionary_t *uhashes,
	    dictionary_t *wordhash,
	    dictionary_t *solved,
	    std::string *salt)
{
  std::string md5hex;
  std::string pin;
  unsigned int i;
  for (i=0; i<=20000000; ++i)
    {
      pin = std::to_string(i);
      md5hex = md5hash(pin + *salt);
      if ((solved->find(md5hex) == solved->end()) &&
	  (uhashes->find(md5hex) != uhashes->end()))
	{
	  std::cout<<"[+] Cracked "
		   <<uhashes->at(md5hex)<<':'
		   <<pin<<std::endl;
	  (*solved)[md5hex] = pin;
	}
    }
  gl.pwgens += i;
}
