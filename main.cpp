#include "headerfile.h"

int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		usage();
		return -1;
	}

	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "could't open device %s: %s\n", dev, errbuf);

		return -1;
	}

	while (true)
	{
		struct pcap_pkthdr *header;
		const u_char *packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0)
			continue;
		if (res == -1 || res == -2)
			break;

		const ether_header *eth = (ether_header *)packet;
		int packetIndex = sizeof(ether_header);

		printf("\n%u bytes captured\n", header->caplen);

		printMACAddress(eth->src);

		printMACAddress(eth->dst);

		if (ntohs(eth->type) == 0x86dd)
		{
			printf("type:IPv6\n");
		}
		else if (ntohs(eth->type) == 0x0800)
		{
			const ip_header *ip = (ip_header *)(packet + packetIndex);
			packetIndex += sizeof(ip_header);

			printf("type:IPv4\n");
			printIPAddress(ip -> ip_src);
			printIPAddress(ip -> ip_dst);
			if (ip->ip_p == 6)
			{
				const tcp_header *tcp = (tcp_header *)(packet + packetIndex);
				packetIndex += sizeof(tcp_header);
				uint32_t tcp_size = (ntohs(ip->ip_len) - ((ip->ip_hl + tcp->th_off) * 4));
				printf("tcp src port: %d\n", ntohs(tcp->th_sport));
				printf("tcp dst port: %d\n", ntohs(tcp->th_dport));
				if (tcp_size > 0)
				{
					//printf("===================================================\n");
					///printpacket(packet + packetIndex, tcp_size);
					//printf("===================================================\n");
				}
				printf("\n\n");
			}
			else if (ip->ip_p == 17)
			{
				const udp_header *udp = (udp_header *)(packet + packetIndex);
				packetIndex += sizeof(udp_header);
				uint32_t udp_size = ntohs(udp->_len);
				printf("udp\n");
				printf("udp src port: %d\n", ntohs(udp->source));
				printf("udp dst port: %d\n", ntohs(udp->dest));

				if (udp_size > 0)
				{
					//printf("===================================================\n");
					//printpacket(packet + packetIndex, udp_size);
					//printf("===================================================\n");
				}
			}

			else if (ip->ip_p == 1)
			{
				const icmp_header *icmp = (icmp_header *)(packet + packetIndex);
				packetIndex += sizeof(icmp_header);
				uint32_t icmp_size = ntohs(ip -> ip_len) - sizeof(ip_header) - sizeof(icmp_header);

				printf("icmp\n");
				printf("type: %d\n", icmp -> icmp_type);
				printf("code: %d\n", icmp -> icmp_code);
				printf("cheaksum: 0x%x\n", ntohs(icmp -> icmp_checksum));
				
				if(icmp -> icmp_type != 3){
					printf("identifier (BE): %d (0x%x)\n", ntohs(icmp -> icmp_identifier),  ntohs(icmp -> icmp_identifier));
					printf("identifier (LE): %d (0x%x)\n", (icmp -> icmp_identifier), (icmp -> icmp_identifier));

					printf("sequence number (BE): %d (0x%x)\n", ntohs(icmp -> icmp_seqnum), ntohs(icmp -> icmp_seqnum));
					printf("sequence number (LE): %d (0x%x)\n", (icmp -> icmp_seqnum), (icmp -> icmp_seqnum));
				}
     			
				printf("icmp_size: %d\n", icmp_size);
				
				if (icmp_size > 0)
				{
					// printf("=======================================================\n");
					// printpacket(packet + packetIndex, icmp_size);
					// printf("=======================================================\n");
					//printf("=======================================================\n");
					//printpacketask(packet, header->caplen);
					//printf("=======================================================\n");
				}

			}
		}

		else if (ntohs(eth->type) == 0x0806)
		{
			const arp_header *arp = (arp_header *)(packet + packetIndex);
			packetIndex += sizeof(arp_header);

			printf("type:arp\n");
			
			printf("hardword type: Ethernet (%d)\n", ntohs(arp -> ar_hrd));
			if(ntohs(arp -> ar_pro) == 0x0800)
				printf("protocol type: IPv4 (0x0800)\n");

			printf("hardword size : %d\n",arp -> ar_hln);
			printf("protocol size : %d\n",arp -> ar_pln);

			printf("opcode: relay (%d)\n",ntohs(arp -> ar_op));

			printMACAddress(arp -> ar_sha);
			printIPAddress(arp -> ar_sip);
			printMACAddress(arp -> ar_tha);
			printIPAddress(arp -> ar_tip);
		}
		printf("=========================================================================\n");
		printpacketask(packet, header->caplen);
		printf("=========================================================================\n");

	}
	printf("\n");
	pcap_close(handle);
	return 0;
}
