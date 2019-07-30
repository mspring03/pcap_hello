#include "headerfile.h"

void usage2()
{
    printf("syntax: pcap_test <interface>\n");
    printf("sample: pcap_test wlan0\n");
}
int main(int argc, char *argv[])
{
    char interface[IFNAMSIZ];
    char senderIPStr[15];
    char targetIPStr[15];
    char senderMacStr[17];
    char targetMacStr[17];
    ip_addr senderIP;
    ip_addr targetIP;
    mac_addr senderMAC;
    mac_addr targetMAC;

    if(argc == 6)
    {
        strncpy(interface, argv[1], IFNAMSIZ);
        strncpy(senderIPStr, argv[2], strlen(argv[2]));
        strncpy(senderMacStr, argv[3], strlen(argv[3]));
        strncpy(targetIPStr, argv[4], strlen(argv[4]));
        strncpy(targetMacStr, argv[5], strlen(argv[5]));
    }
    else
    {
        {
            printf("ERROR\n");
            return -1;
        }
    }

    if(4 != sscanf(senderIPStr, "%d.%d.%d.%d", &senderIP.a, &senderIP.b, &senderIP.c, &senderIP.d)){
            return -1;
        }
        if(6 != sscanf(senderMacStr, "%hhX:%hhX:%hhX:%hhX:%hhX:%hhX", &senderMAC.nic[0], &senderMAC.nic[1], &senderMAC.nic[2], &senderMAC.oui[0], &senderMAC.oui[1], &senderMAC.oui[2])){
            return -1;
        }
        if(4 != sscanf(targetIPStr, "%d.%d.%d.%d", &targetIP.a, &targetIP.b, &targetIP.c, &targetIP.d)){
            return -1;
        }
        if(6 != sscanf(targetMacStr, "%hhx:%hhX:%hhX:%hhX:%hhX:%hhX", &targetMAC.nic[0], &targetMAC.nic[1], &targetMAC.nic[2], &targetMAC.oui[0], &targetMAC.oui[1], &targetMAC.oui[2])){
            return -1;
        }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    while (true)
    {
        if(!arpReply(handle, senderIP, senderMAC, targetIP, targetMAC)){
            return -1;
        }
        // if(inet_aton(senderIPStr, (in_addr *)&senderIP)==0)
        // {
        //     return -1;
        // }
        // if(inet_aton(targetIPStr, (in_addr *)&targetIP) == 0)
        // {
        //     return -1;
        // }
        
        
    }

    pcap_close(handle);
    return 0;
}