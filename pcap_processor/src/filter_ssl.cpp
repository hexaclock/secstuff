#include "pcapstat.h"

#define TLS_SEQS_LENGTH 12

//ignore SSL/TLS alerts (no 00 00 15 xx xx)

const char* tls_seqs[] = {
"16 03 00", "16 03 01",
"16 03 02", "16 03 03",
"14 03 00", "14 03 01",
"14 03 02", "14 03 03",
"17 03 00", "17 03 01",
"17 03 02", "17 03 03"
};

bool mypktcmp(mypkt_t a, mypkt_t b)
{
	return (a.seqnum < b.seqnum);
}

std::vector< std::vector<mypkt> > get_start_pkts(
								   std::vector<mypkt_t> clihellovect,
								   std::vector<mypkt_t> othertlsvect
								   )
{
	int chvectsz = clihellovect.size();
	int otvectsz = othertlsvect.size();
	int i;
	int j;
	mypkt *flowstart;
	mypkt *nextpkt;
	std::vector<mypkt> tempvect;
	std::vector< std::vector<mypkt> > ret;
	
	std::sort(othertlsvect.begin(), othertlsvect.end(), mypktcmp);

	for (i=0; i < chvectsz; ++i)
	{
		flowstart = &(clihellovect[i]);
		tempvect.push_back(*flowstart);
		
		for (j=0; j < otvectsz; ++j)
		{
			nextpkt = &(othertlsvect[j]);
			//if next sequence number follows
			if (flowstart->seqnum == nextpkt->seqnum)
				{
					tempvect.push_back(*nextpkt);
					flowstart = nextpkt;
				}
		}
		
		ret.push_back(tempvect);
		tempvect.clear();
	}
	return ret;
}

void filter_ssl(pcap_t *pcap)
{
	std::vector< std::pair<u_short,u_char*> > bytesvect;
	std::vector<mypkt_t> clihellovect;
	std::vector<mypkt_t> othertlsvect;
	struct pcap_pkthdr *pkthdr;
	struct iphdr *iph;
	mypkt_t pkt;
	struct tcphdr *tcph;
	const u_char *pktdata;
	int ether_type    = 0;
	int ether_offset  = 0;
	u_char *hshkseq;
	u_long ipcount    = 0;
	u_long nmatches   = 0;
	u_char *tempbytes;
	u_int i = 0;

	//convert TLS handshakes into bytes; shove in vector
	for (u_int tmplen=0; i < TLS_SEQS_LENGTH; ++i)
	{
		tmplen = hex_to_bytes(tls_seqs[i], &tempbytes);
		bytesvect.push_back(std::make_pair(tmplen,tempbytes));
	}

	int bvsz = bytesvect.size();
	
	std::cout << "[+] SSL/TLS module initialized" 
				  << std::endl;
	
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
		{
			tcph = (struct tcphdr *) (iph + (iph->ihl * 4));
			
			//loop through TLS sequences
			for (i=0; i < bvsz; ++i)
			{
				hshkseq = NULL;
				//if part of a SSL/TLS handshake
				if ( i<=3 &&
				(hshkseq = (u_char*)memmem(iph, ntohs(iph->tot_len),
							bytesvect[i].second, 
							bytesvect[i].first)) != NULL )
				{
					//if specifically "Client Hello"
					if ( *(hshkseq+5)  == 0x01 &&
						 *(hshkseq+9)  == 0x03 &&
						 *(hshkseq+10) >= 0x00 &&
						 *(hshkseq+10) <= 0x03 )
					{
						pkt.srcip = std::string( (inet_ntoa(*(in_addr*)&(iph->saddr))) );
						pkt.dstip = std::string( (inet_ntoa(*(in_addr*)&(iph->daddr))) );
						pkt.srcport = ntohs(tcph->th_sport);
						pkt.dstport = ntohs(tcph->th_dport);
						pkt.seqnum = ntohl(tcph->th_seq);
						pkt.tot_len = ntohs(iph->tot_len);
						pkt.ihl = iph->ihl;
						clihellovect.push_back(pkt);
						++nmatches;
					}
					//don't need to check other TLS seqs
					break;
				}
				//other SSL/TLS data
				else if (
				(hshkseq = (u_char*)memmem(iph, ntohs(iph->tot_len),
							bytesvect[i].second, 
							bytesvect[i].first)) != NULL )
				{
					pkt.srcip = std::string( (inet_ntoa(*(in_addr*)&(iph->saddr))) );
					pkt.dstip = std::string( (inet_ntoa(*(in_addr*)&(iph->daddr))) );
					pkt.srcport = ntohs(tcph->th_sport);
					pkt.dstport = ntohs(tcph->th_dport);
					pkt.seqnum = ntohl(tcph->th_seq);
					pkt.tot_len = ntohs(iph->tot_len);
					pkt.ihl = iph->ihl;
					othertlsvect.push_back(pkt);
				}
			}
		}
		++ipcount;
	}
	
	std::vector< std::vector<mypkt> > flows = get_start_pkts(clihellovect,
															  othertlsvect);
	int numflows = flows.size();
	int curflowsz = 0;
	mypkt curpkt;
	
	std::cout << "[/] TCP Flows:" << std::endl;
	for (i=0; i<numflows; ++i)
	{
		curflowsz = flows[i].size();
		curpkt = flows[i][0];
		std::cout << curpkt.srcip << ':' << curpkt.srcport << " -> "
				  << curpkt.dstip << ':' << curpkt.dstport << " "
				  << curflowsz << std::endl;
	}

	std::cout << "[+] " << nmatches
			  << " TLS handshakes found with "
			  << othertlsvect.size() << " TLS data packets"
			  << std::endl;
}