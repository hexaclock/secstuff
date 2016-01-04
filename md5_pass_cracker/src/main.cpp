#include "lab2.h"

struct s_env gl;

int main(int argc, char **argv)
{
  double elapsed_time;
  unsigned int timeout;
  std::ifstream hashfile;
  std::ifstream dictfile;
  std::string uhash;
  std::string salt;
  std::string word;
  std::string progname(argv[0]);
  /*tuplevect_t uhashes;*/
  /*md5hash:username*/
  dictionary_t *uhashes = &(gl.uhashes);
  /*std::tuple<std::string,std::string> uhash;*/
  /*md5hash:password*/
  dictionary_t wordhash;
  /*md5hash:password*/
  dictionary_t *solved = &(gl.solved);
  unsigned int i;
  salt = "";
  gl.start_time = time(0);
  setvbuf(stdout, NULL, _IONBF, 0);

  if (argc != 4 && argc != 5)
    panic("usage: "+progname+" <passwordfile> <resultsfile> <timeout> <saltstring>",1);
  hashfile.open(argv[1]);
  gl.results.open(argv[2]);
  dictfile.open(DICTFILE);
  if (!hashfile.is_open())
    panic("[-] FATAL: Failed to open password file",-1);
  if (!gl.results.is_open())
    panic("[-] FATAL: Failed to open results file for writing",-1);
  if ( (timeout = (atoi(argv[3]))) <= 0 )
    panic("[-] FATAL: Must set a timeout greater than 0",-1);
  if ( (argc == 5) && ( (salt = argv[4]) == "" ) )
    panic("[-] FATAL: Not a valid salt",-1);
  if (!dictfile.is_open())
    panic("[-] FATAL: Failed to open dictionary file",-1);

  signal(SIGALRM,alrmh);
  signal(SIGINT,siginth);
  alarm(timeout);
  
  std::string user;
  std::string passhash;
  for (i=0; std::getline(hashfile,uhash); ++i)
    {
      /*check that each line is at least of correct length*/
      if ( uhash.size() < ((2*MD5_DIGEST_LENGTH)+2) )
	printf("[-] Line number %d is invalid\n",i+1);
      else
	{
	  user = uhash.substr(0,uhash.find(':'));
	  passhash = uhash.substr(uhash.find(':')+1);
	  (*uhashes)[passhash] = user;
	  /*uhashes.push_back(std::tuple<std::string,std::string>(passhash,user));*/
	}
    }
  std::cout << "[+] Loaded " << i+1 << " password hashes from file" << std::endl;
  /* build hash table from dict */
  for (i=0; std::getline(dictfile,word); ++i)
    wordhash[md5hash(word+salt)] = word;
  gl.pwgens = i+1;

  std::cout << "[+] Loaded " << i+1 << " words from dictionary file" << std::endl;

  /*combined dictionary and number append attack*/
  /*dict+heuristic1*/
  std::cout << "[/] Started combined dict and number suffix attack" << std::endl;
  numappatk(uhashes,&wordhash,solved,&salt);

  /*l33tspeak heuristic attack*/
  /*heuristic2*/
  std::cout << "[/] Started l33tspeak mutation attack" << std::endl;
  leetatk(uhashes,&wordhash,solved,&salt);

  /*attack numeric passwords up to 20M*/
  std::cout << "[/] Started PIN attack" << std::endl;
  pinatk(uhashes,&wordhash,solved,&salt);

  /*brute force 3-5char passwords*/
  std::cout << "[/] Started brute force attack" << std::endl;
  bruteatk(uhashes,solved,&salt);

  /*turn alarm off*/
  alarm(0);

  /*write cracked hashes to file*/
  for (auto it = solved->begin(); it != solved->end(); ++it)
    gl.results << uhashes->at(it->first) << ':' << it->second << std::endl; 
  
  std::cout << "Elapsed time: "<< time(0) - gl.start_time << " seconds" << std::endl;
  std::cout << "Number of passwords tried: " << gl.pwgens << std::endl;
  return 0;
}
