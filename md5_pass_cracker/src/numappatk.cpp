#include "lab2.h"

void numappatk(dictionary_t *uhashes, 
	       dictionary_t *wordhash, 
	       dictionary_t *solved, std::string *salt)
{
  std::string suffix;
  std::string year;
  std::string md5hex;
  std::string md5hexy;
  int i,j;
  for (auto it = wordhash->begin(); it != wordhash->end(); ++it)
    {
      /*if the hash isn't already solved*/
      if (solved->find(it->first) == solved->end())
	/*if the unmodified hash isn't in the hash:user map
	 * aka if simple dictattack fails
	 */
	if (uhashes->find(it->first) == uhashes->end())
	  /*for (char i='0'; i<='9'; ++i)
	    for (char j='0'; j<='9'; ++j)*/
	  for (i=0,j=1940; i<=99; ++i,++j)
	      {
		suffix = std::to_string(i);
		year = std::to_string(j);
		/*simple 0-99 suffix*/
		md5hex = md5hash(it->second + suffix + *salt);
		/*a lot of people like to use a significant year*/
		md5hexy = md5hash(it->second + year + *salt);
		if (uhashes->find(md5hex) != uhashes->end())
		  {
		    std::cout<<"[+] Cracked "
			     <<uhashes->at(md5hex)<<':'
			     <<it->second + suffix
			     <<std::endl;
		    (*solved)[md5hex] = it->second + suffix;
		  }
		if (uhashes->find(md5hexy) != uhashes->end())
		  {
		    std::cout<<"[+] Cracked "
			     <<uhashes->at(md5hexy)<<':'
			     <<it->second + year
			     <<std::endl;
		    (*solved)[md5hexy] = it->second + year;
		  }
		gl.pwgens += 2;
		suffix.clear();
	      }
	else
	  {
	    std::cout << "[+] Cracked " << uhashes->at(it->first)
		      << ':' << it->second << std::endl;
	    (*solved)[it->first] = wordhash->at(it->first);
	  }
      
    }
}
