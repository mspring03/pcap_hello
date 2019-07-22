#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#define ETH_ALEN 6

void usage() {
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0\n");
}

struct ether_header
{
  uint8_t  dst[ETH_ALEN];        /* destination eth addr        */
  uint8_t  src[ETH_ALEN];        /* source ether addr        */
  uint16_t type;                        /* packet type ID field        */
} __attribute__ ((__packed__));

int main(int argc, char* argv[]) {
	if(argc != 2) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "could't open device %s: %s\n", dev, errbuf);

	return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if(res == 0) continue;
		if(res == -1 || res == -2) break;

		const ether_header *eth = (ether_header *)packet;
		printf("%u bytes captured\n", header->caplen);

		printf("%02X:%02X:%02X:%02X:%02X:%02X\n\n",eth->src[0],eth->src[1],eth->src[2],eth->src[3],eth->src[4],eth->src[5]);


		}

	pcap_close(handle);
	return 0;
}
