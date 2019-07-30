#pragma once
#include <stdio.h>
#include <stdint.h>
#include "headerfile.h"
#include "protocol/all.h"

bool arpSend(pcap_t *handle, mac_addr SRCMAC, mac_addr destNAC, uint16_t arpopcode, ip_addr arpsrcIP, mac_addr arpSrcMAC, ip_addr arpDestIP, mac_addr arpDestMAC);

bool arpReply(pcap_t *handle, ip_addr srcIP, mac_addr srcMAC, ip_addr destIP, mac_addr destMAC);