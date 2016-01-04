#include "lab2.h"

std::string *leetmutate(std::string *s)
{
  std::string *ret = new std::string();
  std::string::iterator it;
  for (it = s->begin(); it != s->end(); ++it)
    {
      if (*it == 'a')
	ret->push_back('@');
      else if (*it == 'e')
	ret->push_back('3');
      else if (*it == 'l')
	ret->push_back('1');
      else
	ret->push_back(*it);
    }
  return ret;
}

void leetatk(dictionary_t *uhashes, 
	     dictionary_t *wordhash,
	     dictionary_t *solved,std::string *salt)
{
  std::string *mutstr;
  std::string md5hex;
  for (auto it = wordhash->begin(); it != wordhash->end(); ++it)
    {
      /*if the hash isn't already solved*/
      if (solved->find(it->first) == solved->end())
	{
	  mutstr = leetmutate(&(it->second));
	  md5hex = md5hash(*mutstr + *salt);
	  /*std::cout<<*mutstr<<std::endl;*/
	  if (uhashes->find(md5hex) != uhashes->end())
	    {
	      std::cout<<"[+] Cracked "
		       << uhashes->at(md5hex) << ':'
		       << *mutstr
		       << std::endl;
	      (*solved)[md5hex] = *mutstr;
	    }
	  ++gl.pwgens;
	}
    }
}
