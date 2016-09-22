// 필요한 헤더들 선언
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <netdb.h>
 
// 발신자의 IP 주소, 컴파일 전에 수정하세요.
#define LOCAL_IP "192.168.237.129"
 
// 체크섬을 구하는 함수 선언/정의.
unsigned short in_cksum(u_short *addr, int len)
{
        int         sum=0;
        int         nleft=len;
        u_short     *w=addr;
        u_short     answer=0;
 
        while (nleft > 1){
        sum += *w++;
        nleft -= 2;
        }
 
        if (nleft == 1){
        *(u_char *)(&answer) = *(u_char *)w ;
        sum += answer;
        }
 
        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        answer = ~sum;
        return(answer);
}
 
// 가상 헤더 구조체 선언
struct pseudohdr {
        u_int32_t   saddr;
        u_int32_t   daddr;
        u_int8_t    useless;
        u_int8_t    protocol;
        u_int16_t   tcplength;
};
 
int main( int argc, char **argv )
{
        unsigned char packet[40];
        int raw_socket, recv_socket;
        int on=1, len ;
        char recv_packet[100], compare[100];
        struct iphdr *iphdr;
        struct tcphdr *tcphdr;
        struct in_addr source_address, dest_address;
        struct sockaddr_in address, target_addr;
        struct pseudohdr *pseudo_header;
        struct in_addr ip;
        struct hostent *target;
        int port;
 
        if( argc < 2 ){
                fprintf( stderr, "Usage : %s Target\n", argv[0] );
                exit(1);
        }
        source_address.s_addr = inet_addr( LOCAL_IP );
        dest_address.s_addr = inet_addr( argv[1] );
        strcpy( compare, argv[1] );
 
        // 인자로 도메인을 주었을 경우 IP로 변환.
        if( dest_address.s_addr == -1 ){
                if( (target = gethostbyname( argv[1] )) == NULL ){
                        fprintf( stderr, "도메인 주소가 올바르지 않습니다.\n" );
                        exit( 1 );
                }
                bcopy( target->h_addr, (char *)&ip.s_addr, target->h_length );
                dest_address.s_addr = ip.s_addr;
                strcpy( compare, inet_ntoa( dest_address ) );
        }
 
        printf( "\n[Wise Scanner Started.]\n\n" );
 
        // 1번에서부터 500번까지 스캔
        for( port=1; port<500; port++ ){
                // raw socket 생성
raw_socket = socket( AF_INET, SOCK_RAW, IPPROTO_RAW );
setsockopt( raw_socket, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on));
 
                // TCP, IP 헤더 초기화
                iphdr = (struct iphdr *)packet;
                memset( (char *)iphdr, 0, 20 );
                tcphdr = (struct tcphdr *)(packet + 20 );
                memset( (char *)tcphdr, 0, 20 );
 
                // TCP 헤더 제작
                tcphdr->source = htons( 777 );
                tcphdr->dest = htons( port );
                tcphdr->seq = htonl( 92929292 );
                tcphdr->ack_seq = htonl( 12121212 );
                tcphdr->doff = 5;
                tcphdr->syn = 1;
                tcphdr->window = htons( 512 );
 
                // 가상 헤더 생성.
                pseudo_header = (struct pseudohdr *)((char*)tcphdr-sizeof(struct pseudohdr));
                pseudo_header->saddr = source_address.s_addr;
                pseudo_header->daddr = dest_address.s_addr;
                pseudo_header->protocol = IPPROTO_TCP;
                pseudo_header->tcplength = htons( sizeof(struct tcphdr) );
 
                // TCP 체크섬 계산.
                tcphdr->check = in_cksum( (u_short *)pseudo_header,
                                sizeof(struct pseudohdr) + sizeof(struct tcphdr) );
 
                // IP 헤더 제작
                iphdr->version = 4;
                iphdr->ihl = 5;
                iphdr->protocol = IPPROTO_TCP;
                iphdr->tot_len = 40;
                iphdr->id = htons( 12345 );
                iphdr->ttl = 60;
                iphdr->saddr = source_address.s_addr;
                iphdr->daddr = dest_address.s_addr;
                // IP 체크섬 계산.
                iphdr->check = in_cksum( (u_short *)iphdr, sizeof(struct iphdr));
 
                address.sin_family = AF_INET;
                address.sin_port = htons( port );
                address.sin_addr.s_addr = dest_address.s_addr;
 
                // 패킷 전송
                sendto( raw_socket, &packet, sizeof(packet), 0x0,
                                        (struct sockaddr *)&address, sizeof(address));
 
                // 응답 패킷의 헤더를 저장할 변수 초기화.
                iphdr = (struct iphdr *)recv_packet;
                tcphdr = (struct tcphdr *)(recv_packet + 20);
memset( (char *)iphdr, 0, 20 );
memset( (char *)tcphdr, 0, 20 );
       
                // 수신용 패킷 생성
                recv_socket = socket( AF_INET, SOCK_RAW, IPPROTO_TCP );
                len = sizeof( target_addr );
 
                // 응답 패킷 검출
                while(1){
                      recvfrom( recv_socket, recv_packet, 100, 0,
(struct sockaddr *)&target_addr, &len );
                      if( strcmp( inet_ntoa(target_addr.sin_addr), compare ) == 0 ){
                           if( ntohs(tcphdr->dest) == 777 ){
                                     // syn 플래그 설정 여부 확인
                                     if( tcphdr->syn == 1 )
                                             printf( "%d Port is open.\n", port );
                                     break;
                             }
                      }
              }
              close( recv_socket );
              close( raw_socket );
        }
        printf( "\n[Scan ended.]\n\n" );
}