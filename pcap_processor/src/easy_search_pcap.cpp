#include "pcapstat.h"

u_int hex_to_bytes(const char *hexstr, u_char **outbytes)
{
	std::vector<u_short> bytevect;
	std::istringstream ss( (std::string(hexstr)) );
	u_short tempbyte;
	u_int i;

	while ( ss >> std::hex >> tempbyte )
		bytevect.push_back(tempbyte);
	
	if ( (*outbytes = (u_char *)calloc(bytevect.size(),
							sizeof(char))) == NULL )
		return 0;
	
	for (i=0; i<(u_int)bytevect.size(); ++i)
		(*outbytes)[i] = bytevect[i];
	
	return i;
}

u_int easy_search_pcap(pcap_t *pcap, const char *match, 
					  bool hex)
{
	struct pcap_pkthdr *pkthdr;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;
	const u_char *pktdata;
	const u_char *data;
	int ether_type    = 0;
	int ether_offset  = 0;
	u_long ipcount    = 0;
	u_long nmatches   = 0;
	u_char *findbytes;
	//don't include '\0' terminator in search
	u_int fblen = strlen(match) - 1;
	
	if (hex)
		fblen = hex_to_bytes(match, &findbytes);
	else
		findbytes = (u_char *)match;
	
	std::cout << "[+] Search module initialized"
				  << std::endl;
			  
	std::cout << "[/] Search results:" << std::endl;
	
	while ( (pcap_next_ex(pcap,&pkthdr,&pktdata) > 0)
			&& (ipcount < MAX_PACKETS) )
	{
		ether_type = ((int)(pktdata[12]) << 8) | (int)pktdata[13];
		if (ether_type == ETHER_TYPE_IP)
			ether_offset = 14;
		/*handle VLAN tags*/
		else if (ether_type == ETHER_TYPE_8021Q)
			ether_offset = 18;
		//start from top of loop if not an ethernet frame
		else
			continue;
		
		iph = (struct iphdr*)(pktdata + ether_offset);
		
		//search entire packet for a possible match, not just data section
		//if (memmem(pkthdr, pkthdr->caplen, findbytes, fblen) != NULL)

		/*
		 *search just the IP packet, not whole eth frame
		 *as per assignment description
		*/
		if (memmem(iph, ntohs(iph->tot_len), 
							findbytes, fblen) != NULL) 
		{
			if (iph->protocol == IPPROTO_TCP)
			{
				tcph = (struct tcphdr *) (iph + (iph->ihl * 4));
				data = pktdata + ether_offset 
					   + sizeof(struct iphdr) + sizeof(struct tcphdr);

				std::cout<<"(TCP) "
						 << inet_ntoa(*(in_addr*)&(iph->saddr)) << ":"
						 << ntohs(tcph->th_sport) << " -> "
						 << inet_ntoa(*(in_addr*)&(iph->daddr)) << ":"
						 << ntohs(tcph->th_dport) << " "
						 //<< data << " "
						 << ipcount << " "
						 << std::endl;
			}	
			else if (iph->protocol == IPPROTO_UDP)
			{
				udph = (struct udphdr *) (iph + (iph->ihl * 4));
				data = pktdata + ether_offset 
					   + sizeof(struct iphdr) + sizeof(struct udphdr);
				std::cout <<"(UDP) "
						  << inet_ntoa(*(in_addr*)&(iph->saddr)) << ":"
						  << ntohs(udph->uh_sport) << " -> "
						  << inet_ntoa(*(in_addr*)&(iph->daddr)) << ":"
						  << ntohs(udph->uh_dport) << " "
						  << ipcount << " "
						  << std::endl;
			}
			else 
			{
				data = pktdata + ether_offset + sizeof(struct iphdr);
				std::cout << "(IP) "
						  << inet_ntoa(*(in_addr*)&(iph->saddr)) << " -> "
						  << inet_ntoa(*(in_addr*)&(iph->daddr)) << " "
						  << ipcount << " "
						  << std::endl;
			}
			
			//std::cout << data << std::endl;
			++nmatches;
		}
		++ipcount;
	}
	
	if (hex)
		free(findbytes);

	return nmatches;
}