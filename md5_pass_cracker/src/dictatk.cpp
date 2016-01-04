#include "lab2.h"

void dictatk(dictionary_t *uhashes, dictionary_t *wordhash, dictionary_t *solved)
{
  for (auto it = uhashes->begin(); it != uhashes->end(); ++it)
    {
      /*if we haven't already cracked the hash*/
      if (solved->find(it->first) == solved->end())
	/*see if the hash is in the hashtable*/
	if (wordhash->find(it->first) != wordhash->end())
	  {
	    /* if so, print to screen and store in solved dict */
	    std::cout << "[+] Cracked " << it->second << ':' << 
	      wordhash->at(it->first) << std::endl;
	    (*solved)[it->first] = wordhash->at(it->first);
	  }
    }
}
