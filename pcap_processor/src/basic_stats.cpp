#include "pcapstat.h"

void basic_stats(pcap_t *pcap)
{
	struct pcap_pkthdr *pkthdr;
	struct iphdr *iph;
	const u_char *pktdata;
	int ether_type    = 0;
	int ether_offset  = 0;
	u_long ipcount    = 0;
	u_long tcpcount   = 0;
	u_long udpcount   = 0;
	u_long icmpcount  = 0;
	u_long othercount = 0;
	
	while ( (pcap_next_ex(pcap,&pkthdr,&pktdata) > 0)
			&& (ipcount < MAX_PACKETS) )
	{
		ether_type = ((int)(pktdata[12]) << 8) | (int)pktdata[13];
		if (ether_type == ETHER_TYPE_IP)
			ether_offset = 14;
		/*handle VLAN tags*/
		else if (ether_type == ETHER_TYPE_8021Q)
			ether_offset = 18;
		else
			continue;
		
		iph = (struct iphdr*)(pktdata + ether_offset);
		if (iph->protocol == IPPROTO_TCP)
			++tcpcount;
		else if (iph->protocol == IPPROTO_UDP)
			++udpcount;
		else if (iph->protocol == IPPROTO_ICMP)
			++icmpcount;
		else
			++othercount;
		
		++ipcount;
	}
	
	std::cout<<"[*] IP Count   : "<<ipcount<<std::endl;
	std::cout<<"[*] TCP Count  : "<<tcpcount<<std::endl;
	std::cout<<"[*] UDP Count  : "<<udpcount<<std::endl;
	std::cout<<"[*] ICMP Count : "<<icmpcount<<std::endl;
	std::cout<<"[*] Other      : "<<othercount<<std::endl;

}