#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include "protocol/all.h"

void usage()
{
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0\n");
}

void printIPAddress(ip_addr ipAddr)
{
	printf("%d.%d.%d.%d\n",ipAddr.a, ipAddr.b, ipAddr.c, ipAddr.d);
}

void printMACAddress(mac_addr mac)
{
	printf("%02X:%02X:%02X:%02X:%02X:%02X\n", mac.oui[0], mac.oui[1], mac.oui[2], mac.nic[0], mac.nic[1], mac.nic[2]);
}

void printpacket(const unsigned char *p, uint32_t size)
{
	int len = 0;
	while (len < size)
	{
		printf("%02x ", *(p++));
		if (!(++len % 16))
			printf("\n");
	}
	if (size % 16)
		printf("\n");
}