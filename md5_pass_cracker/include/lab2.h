#ifndef _LAB2_H_
#define _LAB2_H_

//#define DICTFILE "/usr/share/dict/american-english"
#define DICTFILE "../resource/phpbb.txt"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <unordered_map>
#include <tuple>
#include <openssl/md5.h>
#include <openssl/evp.h>
typedef std::vector< std::tuple<std::string,std::string> > tuplevect_t;
typedef std::unordered_map<std::string,std::string> dictionary_t;

struct s_env {
  time_t start_time;
  std::ofstream results;
  unsigned long long pwgens;
  dictionary_t uhashes;
  dictionary_t solved;
};

extern struct s_env gl;

int main(int argc, char **argv);
char *md5hash(std::string str);
void panic(std::string s, unsigned int n);
void dictatk(dictionary_t *uhashes, dictionary_t *wordhash, dictionary_t *solved);
void alrmh(int sig);
void numappatk(dictionary_t *uhashes, dictionary_t *wordhash, dictionary_t *solved, std::string *salt);
void bruteforce(std::string *salt, dictionary_t *uhashes, dictionary_t *solved, int passlen);
void bruteatk(dictionary_t *uhashes, dictionary_t *solved, std::string *salt);
void leetatk(dictionary_t *uhashes, dictionary_t *wordhash, dictionary_t *solved, std::string *salt);
std::string *leetmutate(std::string *s);
void pinatk(dictionary_t *uhashes,
	    dictionary_t *wordhash,
	    dictionary_t *solved,
	    std::string *salt);
void siginth(int sig);
#endif
