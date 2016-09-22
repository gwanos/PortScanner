#ifndef ADDRESS_H
#define ADDRESS_H

#include "Packet.h"

typedef enum 
{
	ICMP = 1, TCP = 6, UDP = 17
}Protocols;

char * GetIPAddress(char * interfaceName);
char * GetProtocolName(IPHeader * ipHeader);

#endif