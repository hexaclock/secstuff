#ifndef _PCAPSTAT_H_
#define _PCAPSTAT_H_

#define ETHER_TYPE_IP (0x0800)
#define ETHER_TYPE_8021Q (0x8100)
/*We will process a maximum of 5M packets*/
#define MAX_PACKETS 5000000

/* C stuff */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>  

/* C++ stuff */
#include <string>
#include <sstream>
#include <iostream>
#include <vector>
#include <algorithm>
#include <utility>
#include <stdint.h>

typedef struct mypkt_t 
{
	std::string srcip;
	std::string dstip;
	unsigned short srcport;
	unsigned short dstport;
	unsigned long seqnum;
	unsigned short tot_len;
	unsigned short ihl;
	//unsigned long nextseqnum;
	//unsigned long flowlen;
	//struct mypkt *nextpkt;
} mypkt;

int main(int argc, char **argv);
void basic_stats(pcap_t *pcap);
u_int easy_search_pcap(pcap_t *pcap, const char *match, bool hex);
u_int hex_to_bytes(const char *hexstr, u_char **outbytes);
void filter_ssl(pcap_t *pcap);

#endif
