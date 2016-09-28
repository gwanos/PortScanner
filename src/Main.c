#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>

#include "Protocol.h"
#include "Packet.h"
#include "HandleError.h"

pthread_mutex_t mutx;
char targetIPAddress[128];
struct in_addr sourceAddress, destAddress, ip;

int main( int argc, char *argv[] )
{
	int raw_socket, recv_socket;
	int on = 1;
	struct hostent * target;
	struct timeval start, end;
    long mtime, seconds, useconds;
	
	pthread_t send_thread, recv_thread;
	void * thread_return;
	
	gettimeofday(&start, NULL);
	// A critical section begins	
	pthread_mutex_init(&mutx, NULL);

	if( argc < 2 )
	{
		fprintf( stderr, "Usage : %s target\n", argv[0] );
		exit(1);
	}

	char * localIP = GetIPAddress("ens33");
	sourceAddress.s_addr = inet_addr( localIP );
	destAddress.s_addr = inet_addr( argv[1] );
	strcpy( targetIPAddress, argv[1] );

	// Translate domain to IP address
	if ( destAddress.s_addr == -1 )
	{
		if( ( target = gethostbyname( argv[1] ) ) == NULL )
		{
			fprintf( stderr, "Domain address is improper.\n" );
			exit(1);
		}
		bcopy( target->h_addr, (char *)&ip.s_addr, target->h_length );
		destAddress.s_addr = ip.s_addr;
		strcpy( targetIPAddress, inet_ntoa( destAddress ) );
	}

	// Create send socket(raw socket)
	if( (raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
		DisplayErrorMessage("socket() error");
	setsockopt( raw_socket, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on) );

	// Create receive socket
	if( ( recv_socket = socket( PF_INET, SOCK_RAW, IPPROTO_TCP ) ) == -1 )
		DisplayErrorMessage("recv_socket() error.");

	printf("\n### Starting GHScanner... ###\n");
	printf("Scan report for %s\n\n", targetIPAddress);

	pthread_create(&send_thread, NULL, SendPacket, (void *)&raw_socket);
	pthread_create(&recv_thread, NULL, ReceivePacket, (void *)&recv_socket);
	pthread_join(send_thread, &thread_return);
	pthread_detach(recv_thread);

	// Calculate scanning time
	gettimeofday(&end, NULL);
    seconds  = end.tv_sec  - start.tv_sec;
    useconds = end.tv_usec - start.tv_usec + 0.5;
	printf( "\n### Scan finished... Execution time: %ld.%ld seconds ###\n\n", seconds, useconds);

	// A critical section ends
	pthread_mutex_destroy(&mutx);
	close( recv_socket );
	close( raw_socket );
	
	return 0;
}
