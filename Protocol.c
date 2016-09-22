#include <stdio.h>
#include <unistd.h>
#include <string.h> 
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "Protocol.h"

char * GetIPAddress(char * interfaceName)
{
	int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interfaceName, IFNAMSIZ-1);	// IP address attached to interface "ens33"
    ioctl(fd, SIOCGIFADDR, &ifr);

    char * ret = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
    close(fd);
	return ret;
}

char * GetProtocolName(IPHeader * ipHeader)
{
	char * ret = "";
	switch(ipHeader->protocol)
	{
		case ICMP: ret = "icmp"; break;
		case TCP: ret = "tcp"; break;
		case UDP: ret = "udp"; break;
		default: ret = "other"; break;
	}
	return ret;
}
