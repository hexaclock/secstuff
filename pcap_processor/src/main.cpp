#include "pcapstat.h"

void print_search_usage(char *prgname, bool die)
{
	std::cout<< std::endl
			 << "Module usage: " << prgname
			 << " <pcapfile> search [-hex] <searchterm>"
			 << std::endl;
	if (die)
		exit(2);
}

pcap_t *easy_open_pcap(const char *pcapfname)
{
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcaphandle = NULL;
	
	pcaphandle = pcap_open_offline(pcapfname, pcap_errbuf);
	if (pcaphandle == NULL)
	{
		std::cout<<"[-] Could not open PCAP file"<<std::endl;
		exit(-1);
	}
	
	return pcaphandle;
}

int main(int argc, char **argv)
{
	pcap_t *pcaphandle = NULL;
	time_t start_time;
	time_t end_time;
	
	
	if (argc < 2)
	{
		std::cout<<"Usage: " << std::string(argv[0])
				 << " <pcapfile> [optional_module]"
				 << std::endl << "Implemented modules: search, ssl"
				 << std::endl << std::endl;
		return 1;
	}
	
	pcaphandle = easy_open_pcap(argv[1]);
	//begin timed code
	start_time = time(0);
	basic_stats(pcaphandle);
	end_time = time(0);
	//end timed code
	std::cout<< "[*] Time taken : " << end_time - start_time
			 << " seconds" << std::endl;
			 
	pcap_close(pcaphandle);

	//if module argument has been specified
	if (argc >= 3)
	{
		if (!strcmp(argv[2],"search"))
		{
			u_int nmatches = 0;
			std::cout << std::endl;
			if (argc != 4 && argc != 5)
				print_search_usage(argv[0], true);
			else if (argc == 5)
			{
				pcaphandle = easy_open_pcap(argv[1]);
				if (!strcmp(argv[3],"-hex"))
					nmatches = easy_search_pcap(pcaphandle, 
								(const char*)argv[4], true);
				else
					print_search_usage(argv[0], true);
				pcap_close(pcaphandle);
			}
			else
			{
				pcaphandle = easy_open_pcap(argv[1]);
				nmatches = easy_search_pcap(pcaphandle, 
							(const char*)argv[3], false);
				pcap_close(pcaphandle);
			}
			std::cout<<std::endl<< "[+] " << nmatches
								<< " matches found" << std::endl;
		}
		else if (!strcmp(argv[2],"ssl"))
		{
			pcaphandle = easy_open_pcap(argv[1]);
			filter_ssl(pcaphandle);
			pcap_close(pcaphandle);
		}
		else
		{
			std::cout<< std::endl
					 << "[-] Module not implemented: " 
					 << argv[2]
					 << std::endl;
		}
		
	}
	
	std::cout<<std::endl;
	
	return 0;
}
