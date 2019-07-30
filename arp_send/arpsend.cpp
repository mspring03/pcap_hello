#include "headerfile.h"

bool arpSend(pcap_t *handle, mac_addr SRCMAC, mac_addr destNAC, uint16_t arpopcode, ip_addr arpsrcIP, mac_addr arpSrcMAC, ip_addr arpDestIP, mac_addr arpDestMAC) {
    uint8_t buffer[1500];
        int packetIndex = 0;
        ether_header eth;
        eth.type = htons(ETHERTYPE_ARP);
        mac_addr src;
        src.oui[0] = SRCMAC.oui[0];
        src.oui[1] = SRCMAC.oui[1];
        src.oui[2] = SRCMAC.oui[2];
        src.nic[0] = SRCMAC.nic[0];
        src.nic[1] = SRCMAC.nic[1];
        src.nic[2] = SRCMAC.nic[2];
        eth.src = src;
        
        mac_addr dest;
        dest.oui[0] = destNAC.oui[0];
        dest.oui[1] = destNAC.oui[1];
        dest.oui[2] = destNAC.oui[2];
        dest.nic[0] = destNAC.nic[0];
        dest.nic[1] = destNAC.nic[1];
        dest.nic[2] = destNAC.nic[2];
        eth.dst = dest;
        memcpy(buffer, &eth, sizeof(ether_header));
        packetIndex += sizeof(ether_header);

        arp_header arp;

        arp.ar_hrd = 1;
        arp.ar_pro = htons(0x0800);
        arp.ar_hln = 6;
        arp.ar_pln = 4;
        arp.ar_op = arpopcode;

        mac_addr ar_sha;
        ar_sha.oui[0] = arpSrcMAC.oui[0];
        ar_sha.oui[1] = arpSrcMAC.oui[1];
        ar_sha.oui[2] = arpSrcMAC.oui[2];
        ar_sha.nic[0] = arpSrcMAC.nic[0];
        ar_sha.nic[1] = arpSrcMAC.nic[1];
        ar_sha.nic[2] = arpSrcMAC.nic[2];
        arp.ar_sha = ar_sha;

        ip_addr ar_sip;
        ar_sip.a = arpsrcIP.a;
        ar_sip.b = arpsrcIP.b;
        ar_sip.c = arpsrcIP.c;
        ar_sip.d = arpsrcIP.d;
        arp.ar_sip = ar_sip;

        mac_addr ar_tha;
        ar_tha.oui[0] = arpDestMAC.oui[0];
        ar_tha.oui[1] = arpDestMAC.oui[1];
        ar_tha.oui[2] = arpDestMAC.oui[2];
        ar_tha.nic[0] = arpDestMAC.nic[0];
        ar_tha.nic[1] = arpDestMAC.nic[1];
        ar_tha.nic[2] = arpDestMAC.nic[2];
        arp.ar_tha = ar_tha;

        ip_addr ar_tip;
        ar_tip.a = arpDestIP.a;
        ar_tip.b = arpDestIP.b;
        ar_tip.c = arpDestIP.c;
        ar_tip.d = arpDestIP.d;
        arp.ar_tip = ar_tip;

        memcpy(buffer + packetIndex, &arp, sizeof(arp_header));
        packetIndex += sizeof(arp_header);


        /* ARP ~~ */

        if(pcap_sendpacket(handle,buffer,packetIndex) != 0) {
            printf("Send Fail.\n");
        }
}

// bool arpRequest(pcap_t *handle, ip_addr srcIP, mac_addr srcMAC, ip_addr destIP) {
//     mac_addr broadcastMAC;
//     memset(&broadcastMAC,0xff, sizeof(mac_addr));
//     mac_addr responseMAC;
//     memset(&broadcastMAC,0xff, sizeof(mac_addr));

// }

bool arpReply(pcap_t *handle, ip_addr srcIP, mac_addr srcMAC, ip_addr destIP, mac_addr destMAC) {
    return arpSend(handle, srcMAC, destMAC, ARPOP_REPLY, srcIP, srcMAC, destIP, destMAC);
}