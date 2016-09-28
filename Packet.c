#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>  
#include <sys/stat.h>  
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include "Protocol.h"
#include "Packet.h"

extern char targetIPAddress[128];
extern struct in_addr sourceAddress, destAddress, ip;

const int localPort = 52001;
const int maxPortNumber = 10000;
const int ipVersion = 4;
const int windowSize = 512;
const int packetId = 777;
const int timeToLive = 60;

void SetTCPHeader(TCPHeader * out, int srcPort, int destPort, int seqNum, int ackSeqNum, int offset, int synFlag, int windowSize)
{
	out->source = htons(srcPort); 
	out->dest = htons(destPort);
	out->seq = htonl(seqNum);			// Seq Num
	out->ack_seq = htonl(ackSeqNum);	// Ack Num
	out->doff = offset;					// offset
	out->syn = synFlag;					// SYN flag
	out->window = htons(windowSize);	// Window size
	out->check = 0x0000;
}

PseudoHeader SetPseudoHeader(int protocol, TCPHeader * tcphdr)
{
	PseudoHeader ret;
	ret.srcIPAddr = sourceAddress.s_addr;
	ret.destIPAddr = destAddress.s_addr;
	ret.reserved = 0;
	ret.protocol = protocol;		
	ret.headerLength = htons( sizeof(TCPHeader) );
	memcpy( &(ret.tcpHeader), tcphdr, sizeof(TCPHeader) );

	return ret;
}

void SetIPHeader(IPHeader * out, int version, int length, int tos, int totalLength, int id, int ttl, int protocol)
{
	out->version = version; 		// IP Version
	out->ihl = length;	 			// IP Header Length
	out->tos = tos;
	out->tot_len = totalLength;
	out->id = htons(id); 			// Distinguish each packets.
	out->ttl = ttl; 			
	out->check = 0x0000;
	out->protocol = protocol; 	 
	out->saddr = sourceAddress.s_addr; 	// Source IP
	out->daddr = destAddress.s_addr;	// Destination IP
}

unsigned short CalculateChecksum( unsigned short *buf, int len )
{
	register unsigned long sum = 0;

	while( len-- )
		sum += *buf++;

	sum = ( sum >> 16 ) + ( sum & 0xFFFF);
	sum += ( sum >> 16 );

	return (unsigned short)(~sum);
}

void * SendPacket(void *arg)
{
	int raw_socket = *((int *)arg);
	unsigned char packet[40];	// TCP header(20Bytes) + IP header(20Bytes);

	IPHeader * iphdr;
	TCPHeader * tcphdr;
	PseudoHeader psdhdr;
	struct sockaddr_in destInfo;

	// Scan starts
	for(int targetPort = 1; targetPort < maxPortNumber; targetPort++)
	{
		// Initialize
		iphdr = (IPHeader *)packet; 
		tcphdr = (TCPHeader *)(packet + sizeof(IPHeader));
		memset( packet, 0x00, sizeof(IPHeader) + sizeof(TCPHeader) ); 

		// Set TCP header
		SetTCPHeader(tcphdr, localPort, targetPort, 23456, 0x00, 5, 1, windowSize);
		psdhdr = SetPseudoHeader(IPPROTO_TCP, tcphdr);
		SetIPHeader(iphdr, ipVersion, 5, 0, 40, packetId, timeToLive, IPPROTO_TCP);

		// Calcalate checksum
		tcphdr->check = CalculateChecksum((unsigned short *)&psdhdr, sizeof(PseudoHeader) / sizeof(unsigned short));
		iphdr->check = CalculateChecksum((unsigned short *)&iphdr, sizeof(IPHeader) / sizeof(unsigned short));

		// Config and send a packet
		destInfo.sin_family = AF_INET;
		destInfo.sin_port = htons( targetPort );
		destInfo.sin_addr.s_addr = destAddress.s_addr;

		sendto( raw_socket, &packet, sizeof(packet), 0, (struct sockaddr *)&destInfo, sizeof(destInfo));
	}
	return NULL;
}

void * ReceivePacket(void *arg)
{
	// Initialize
	int recv_socket = *((int *)arg); 
	int length;
	int portNumber;
	char recv_packet[100]; 
	char * protocolName;
	struct sockaddr_in destInfo;
	TCPHeader * tcpHeader;
	IPHeader * ipHeader;
	
	memset( &recv_packet, 0, sizeof(char)*100);
	ipHeader = (IPHeader *)recv_packet;
	tcpHeader = (TCPHeader *)(recv_packet + sizeof(IPHeader));
	length = sizeof(destInfo);

	// Receive and display
	printf("PORT\t\tSTATE\n");
	while(1)
	{
		recvfrom( recv_socket, recv_packet, sizeof(recv_packet), 0, (struct sockaddr *)&destInfo, &length);

		if((strcmp( inet_ntoa( destInfo.sin_addr ), targetIPAddress ) == 0) && (ntohs( tcpHeader->dest ) == localPort)) 
		{
			if(tcpHeader->syn == 1)	// syn = 1: open / rst = 1 : closed
			{
				protocolName = GetProtocolName(ipHeader);
				portNumber = ntohs(tcpHeader->source);
				if(portNumber > 999)
					printf("%d/%s\topen\n", portNumber, protocolName);
				else
					printf("%d/%s\t\topen\n", portNumber, protocolName);	
			}
		}
	}

	return NULL;
}