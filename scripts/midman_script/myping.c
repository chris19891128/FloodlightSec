/* Must be root or SUID 0 to open RAW socket */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <arpa/inet.h>
#define START_ID 4000
#define DATA_LEN 56
#define PACK_LEN 84

// 84 is the length for ip datagram

int main(int argc, char *argv[])
{
  int s, i;
  char buf[100];
  struct ip *ip = (struct ip *)buf;
  struct icmphdr *icmp = (struct icmphdr *)(ip + 1);
  struct hostent *hp, *hp2;
  struct sockaddr_in dst;
  int offset;
  int on;
  int num = 100;
 
  if(argc < 4){
     printf("\nUsage: %s <saddress> <dstaddress> [number]\n", argv[0]);
     printf("- saddress is the spoofed source address\n");
     printf("- dstaddress is the target\n");
     printf("- number is the number of packets to send, 100 is the default\n");
     exit(1);
   }

  /* Copy the packet number */
  num = atoi(argv[3]);
 
  /* Loop based on the packet number */
  for(i=1;i<=num;i++){
    on = 1;
    bzero(buf, sizeof(buf));
 
    /* Create RAW socket */
    if((s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0){
      perror("socket() error");
      exit(1);
    }
 
    /* socket options, tell the kernel we provide the IP structure */
    if(setsockopt(s, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0){
      perror("setsockopt() for IP_HDRINCL error");
      exit(1);
    }
 
    if((ip->ip_dst.s_addr = inet_addr(argv[2])) == -1){
       fprintf(stderr, "%s: Can't resolve, unknown host.\n", argv[2]);
       exit(1);
    }
 
    if((ip->ip_src.s_addr = inet_addr(argv[1])) == -1){
             fprintf(stderr, "%s: Can't resolve, unknown host\n", argv[1]);
             exit(1);
    }
    
    printf("Sending to %s from spoofed %s\n", inet_ntoa(ip->ip_dst), argv[1]);
 
    /* Ip structure, check the ip.h */
    ip->ip_v = 4;
    ip->ip_hl = sizeof*ip >> 2;
    ip->ip_tos = 0;
    ip->ip_len = htons(sizeof(buf));
    ip->ip_id = htons(START_ID + i);
    ip->ip_off = htons(0);
    ip->ip_ttl = 64;
    ip->ip_p = 1;
    ip->ip_sum = 0; /* Let kernel fills in */
    /* icmp header */
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->checksum = htons(~(ICMP_ECHO << 8));
    /* data */    
    /*char * data = (char*)(icmp + 1);
    char * tmp;
    * data = (char) i;
    for(tmp = data + 1; tmp < data + DATA_LEN; tmp++){
       *tmp = rand()%26 + 65;
    }
    */


    /* sending time */
    dst.sin_addr = ip->ip_dst;
    dst.sin_family = AF_INET; 
    if(sendto(s, buf, PACK_LEN, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0){      
       fprintf(stderr, "offset %d: ", offset);
       perror("sendto() error");
    } else
       printf("sendto() is OK.\n");
    /* close socket */
    close(s);
    sleep(3);
  }
  return 0;
}
