#pragma once
#include <stdio.h>
#include <stdint.h>
#include "protocol/all.h"

void usage();
void printIPAddress(ip_addr ipAddr);
void printMACAddress(mac_addr mac);
void printpacket(const unsigned char *p, uint32_t size);
void printpacketask(const unsigned char *p, uint32_t size);
void cheakhttp(const u_char *data);
