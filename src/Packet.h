#ifndef PACKET_H
#define PACKET_H

#include <linux/ip.h>
#include <linux/tcp.h>

// pseudo header for calculating checksum
typedef struct _PseudoHeader
{
	u_int32_t srcIPAddr; 
	u_int32_t destIPAddr; 
	u_int8_t reserved; 
	u_int8_t protocol; 
	u_int16_t headerLength; 
	struct tcphdr tcpHeader;
}PseudoHeader;
typedef struct tcphdr TCPHeader;
typedef struct iphdr IPHeader;

void SetTCPHeader(TCPHeader * out, int srcPort, int destPort, int seqNum, int ackSeqNum, int offset, int synFlag, int windowSize);
PseudoHeader SetPseudoHeader(int protocol, TCPHeader * tcphdr);
void SetIPHeader(IPHeader * out, int version, int length, int tos, int totalLength, int id, int ttl, int protocol);
unsigned short CalculateChecksum( unsigned short *buf, int len );
void * SendPacket( void * arg );
void * ReceivePacket( void * arg );

#endif