#include <stdlib.h>
#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <cstring>
#include <arpa/inet.h>
#include <sys/uio.h> // For writev


/* this normally comes from the pcap.h header file, but we'll just be using
 * a few specific pieces, so we'll add them here
 *
 * The first record in the file contains saved values for some
 * of the flags used in the printout phases of tcpdump.
 */

typedef int32_t bpf_int32;
typedef u_int32_t bpf_u_int32;

/* every pcap file starts with this structure */
struct pcap_file_header {
    bpf_u_int32 magic;
    u_short version_major;
    u_short version_minor;
    bpf_int32 thiszone;	/* gmt to local correction; this is always 0 */
    bpf_u_int32 sigfigs;	/* accuracy of timestamps; this is always 0 */
    bpf_u_int32 snaplen;	/* max length saved portion of each pkt */
    bpf_u_int32 linktype;	/* data link type (LINKTYPE_*) */
};

// Define the magic number (normal and swapped for different endians) and version numbers for pcap files
#define PCAP_MAGIC         0xa1b2c3d4
#define PCAP_SWAPPED_MAGIC 0xd4c3b2a1
#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4

/*
 * Generic per-packet information, as supplied by libpcap.
 * this is the second record in the file, and every packet starts
 * with this structure (followed by the packet date bytes)
 */
struct pcap_pkthdr {
    bpf_u_int32 ts_secs;		/* time stamp */
    bpf_u_int32 ts_usecs;	/* time stamp */
    bpf_u_int32 caplen;	/* length of portion present */
    bpf_u_int32 len;	/* length of this packet (off wire) */
};


int debug = 1;
int swapped = 0;
int no_name_resolution = 0;


struct eth_hdr {
    unsigned char dst[6];  // Destination MAC address
    unsigned char src[6];  // Source MAC address
    unsigned short type;   // EtherType field
};

struct ip_hdr {
    unsigned char ver_ihl;    // Version (4 bits) + Internet header length (4 bits)
    unsigned char tos;        // Type of service (1 byte)
    unsigned short len;       // Total length (2 bytes)
    unsigned short id;        // Identification (2 bytes)
    unsigned short frag_off;  // Fragment offset field (2 bytes)
    unsigned char ttl;        // Time to live (1 byte)
    unsigned char proto;      // Protocol (1 byte)
    unsigned short check;     // Header checksum (2 bytes)
    unsigned int src;         // Source address (4 bytes)
    unsigned int dst;         // Destination address (4 bytes)
};

struct tcp_hdr {
    unsigned short sport;    // Source port (2 bytes)
    unsigned short dport;    // Destination port (2 bytes)
    unsigned int seq;        // Sequence number (4 bytes)
    unsigned int ack;        // Acknowledgment number (4 bytes)
    unsigned char offset_res; // Data offset (4 bits) and reserved bits (4 bits) (1 byte)
    unsigned char flags;     // Flags (control bits) (1 byte)
    unsigned short win;      // Window size (2 bytes)
    unsigned short csum;     // Checksum (2 bytes)
    unsigned short urp;      // Urgent pointer (2 bytes)
};

struct udp_hdr {
    unsigned short sport;    // Source port (2 bytes)
    unsigned short dport;    // Destination port (2 bytes)
    unsigned short len;      // Datagram length (2 bytes)
    unsigned short csum;     // Checksum (2 bytes)
};

struct arp_hdr {
    unsigned short hw_type;  // Hardware type (2 bytes)
    unsigned short proto_type; // Protocol type (2 bytes)
    unsigned char hw_len;    // Hardware address length (1 byte)
    unsigned char proto_len; // Protocol address length (1 byte)
    unsigned short opcode;   // Operation code (request/reply) (2 bytes)
    unsigned char sender_mac[6]; // Sender hardware address (MAC) (6 bytes)
    unsigned char sender_ip[4];  // Sender protocol address (IP) (4 bytes)
    unsigned char target_mac[6]; // Target hardware address (MAC) (6 bytes)
    unsigned char target_ip[4];  // Target protocol address (IP) (4 bytes)
};

struct icmp_hdr {
    unsigned char type;       // ICMP message type
    unsigned char code;       // ICMP message code
    unsigned short checksum;  // ICMP checksum
    unsigned short id;        // Identifier (used for echo requests/replies)
    unsigned short seq;       // Sequence number (used for echo requests/replies)
};

void print_pcap_header(struct pcap_file_header *pfh) {
    printf("PCAP File Header:\n");
    printf("   |-Magic Number       : 0x%08x\n", pfh->magic);
    printf("   |-Version Major      : %d\n", pfh->version_major);
    printf("   |-Version Minor      : %d\n", pfh->version_minor);
    printf("   |-This Zone          : %d\n", pfh->thiszone);
    printf("   |-Sigfigs            : %d\n", pfh->sigfigs);
    printf("   |-Snaplen            : %d\n", pfh->snaplen);
    printf("   |-Linktype           : %d\n", pfh->linktype);
}

void print_pcap_packet_header(struct pcap_pkthdr *pph) {
    printf("PCAP Packet Header:\n");
    printf("   |-Timestamp Seconds  : %u\n", pph->ts_secs);
    printf("   |-Timestamp Microsecs: %u\n", pph->ts_usecs);
    printf("   |-Captured Length    : %u\n", pph->caplen);
    printf("   |-Original Length    : %u\n", pph->len);
}

void print_ethernet(struct eth_hdr *peh) {
    printf("Ethernet Header\n");
    printf("   |-Destination Address : %02x:%02x:%02x:%02x:%02x:%02x \n", 
           peh->dst[0], peh->dst[1], peh->dst[2], peh->dst[3], peh->dst[4], peh->dst[5]); // Goes bit by bit through the Destination MAC address and prints it in hex
    printf("   |-Source Address      : %02x:%02x:%02x:%02x:%02x:%02x \n", 
           peh->src[0], peh->src[1], peh->src[2], peh->src[3], peh->src[4], peh->src[5]); // Goes bit by bit through the Source MAC address and prints it in hex
    printf("   |-Protocol            : %04x \n", ntohs(peh->type));
}

// This function prints the IP header and is only used for debugging
void print_ip(struct ip_hdr *iph) {
    printf("IP Header\n");
    printf("   |-Version        : %d\n", (iph->ver_ihl >> 4)); // version is in the first 4 bits, so we right shift
    printf("   |-Header Length  : %d bytes\n", (iph->ver_ihl & 0x0F) * 4); // header length is in the last 4 bits, so we mask with 0x0F (00001111) and multiply by 4 to get bytes
    printf("   |-Type of Service: %d\n", iph->tos);
    printf("   |-Total Length   : %d\n", ntohs(iph->len));
    printf("   |-Identification : %d\n", ntohs(iph->id));
    printf("   |-Fragment Offset: %d\n", (ntohs(iph->frag_off) & 0x1FFF) * 8); // mask with 0x1FFF (0001111111111111) to get rid of flags in the first 3 bits and multiply by 8 to get bytes
    printf("   |-Time to Live   : %d\n", iph->ttl);
    printf("   |-Protocol       : %d\n", iph->proto);
    printf("   |-Header Checksum: %d\n", ntohs(iph->check));
    printf("   |-Source IP      : %s\n", inet_ntoa(*(struct in_addr *)&iph->src));
    printf("   |-Destination IP : %s\n", inet_ntoa(*(struct in_addr *)&iph->dst));
}

// Prints a summary of the IP header
void print_ip_summary(struct ip_hdr *iph) {
    printf("\tIP:\tVers:\t%d\n", (iph->ver_ihl >> 4)); // Version is in the first 4 bits, so we right shift
    printf("\t\tHlen:\t%d bytes\n", (iph->ver_ihl & 0x0F) * 4); // Header length is in the last 4 bits, so we mask with 0x0F (00001111) and multiply by 4 to get bytes
    printf("\t\tSrc:\t%s\t\n", inet_ntoa(*(struct in_addr *)&iph->src));
    printf("\t\tDest:\t%s\t\n", inet_ntoa(*(struct in_addr *)&iph->dst));
    printf("\t\tTTL:\t%d\n", iph->ttl);
    printf("\t\tFrag Ident:\t%d\n", ntohs(iph->id));
    printf("\t\tFrag Offset:\t%d\n", (ntohs(iph->frag_off) & 0x1FFF) * 8);  // Mask with 0x1FFF (0001111111111111) to get rid of flags in the first 3 bits and multiply by 8 to get bytes
    printf("\t\tFrag DF:\t%s\n", (ntohs(iph->frag_off) & 0x4000) ? "yes" : "no"); // Check if the Don't Fragment (DF) flag is set by masking with 0x4000 (0100000000000000)
    printf("\t\tFrag MF:\t%s\n", (ntohs(iph->frag_off) & 0x2000) ? "yes" : "no"); // Check if the More Fragments (MF) flag is set by masking with 0x2000 (0010000000000000)
    printf("\t\tIP CSum:\t%d\n", ntohs(iph->check));
    printf("\t\tType:\t0x%x\t", iph->proto);
    if (iph->proto == IPPROTO_TCP) {
        printf("(TCP)\n");
    } else if (iph->proto == IPPROTO_UDP) {
        printf("(UDP)\n");
    } else {
        printf("\n");
    }
}

// Prints a summary of the TCP header
void print_tcp_summary(struct tcp_hdr *tcph) {
    printf("\tTCP:\tSport:\t%d\n", ntohs(tcph->sport));
    printf("\t\tDport:\t%d\n", ntohs(tcph->dport));
    printf("\t\tFlags:\t%c%c%c%c%c%c\n",
        (tcph->flags & 0x01) ? 'F' : '-', // Check if the FIN flag (bit 0) is set
        (tcph->flags & 0x02) ? 'S' : '-', // Check if the SYN flag (bit 1) is set
        (tcph->flags & 0x04) ? 'R' : '-', // Check if the RST flag (bit 2) is set
        (tcph->flags & 0x08) ? 'P' : '-', // Check if the PSH flag (bit 3) is set
        (tcph->flags & 0x10) ? 'A' : '-', // Check if the ACK flag (bit 4) is set
        (tcph->flags & 0x20) ? 'U' : '-'); // Check if the URG flag (bit 5) is set
    printf("\t\tSeq:\t%u\n", ntohl(tcph->seq));
    printf("\t\tACK:\t%u\n", ntohl(tcph->ack));
    printf("\t\tWin:\t%d\n", ntohs(tcph->win));
    printf("\t\tCSum:\t%d\n", ntohs(tcph->csum));
}

// Prints a summary of the UDP header
void print_udp_summary(struct udp_hdr *udph) {
    printf("\tUDP:\tSport:\t%d\n", ntohs(udph->sport));
    printf("\t\tDport:\t%d\n", ntohs(udph->dport));
    printf("\t\tDGlen:\t%d\n", ntohs(udph->len));
    printf("\t\tCSum:\t%d\n", ntohs(udph->csum));
}

// Prints a summary of the ARP header
void print_arp_summary(struct arp_hdr *arph) {
    printf("\tARP:\tHWtype:\t%d\n", ntohs(arph->hw_type));
    printf("\t\thlen:\t%d\n", arph->hw_len);
    printf("\t\tplen:\t%d\n", arph->proto_len);
    printf("\t\tOP:\t%d ", ntohs(arph->opcode));
    if (ntohs(arph->opcode) == 1) {
        printf("(ARP request)\n");
    } else if (ntohs(arph->opcode) == 2) {
        printf("(ARP reply)\n");
    } else {
        printf("\n");
    }
    printf("\t\tHardware:\t%02x:%02x:%02x:%02x:%02x:%02x\n",
           arph->sender_mac[0], arph->sender_mac[1], arph->sender_mac[2],
           arph->sender_mac[3], arph->sender_mac[4], arph->sender_mac[5]);
    printf("\t\t\t==>\t%02x:%02x:%02x:%02x:%02x:%02x\n",
           arph->target_mac[0], arph->target_mac[1], arph->target_mac[2],
           arph->target_mac[3], arph->target_mac[4], arph->target_mac[5]);
    printf("\t\tProtocol:\t%d.%d.%d.%d\t\n",
           arph->sender_ip[0], arph->sender_ip[1], arph->sender_ip[2], arph->sender_ip[3]);
    printf("\t\t\t==>\t%d.%d.%d.%d\t\n",
           arph->target_ip[0], arph->target_ip[1], arph->target_ip[2], arph->target_ip[3]);
}

void print_icmp_summary(struct icmp_hdr *icmph) {
    printf("\tICMP:\tType:\t%d\n", icmph->type);
    printf("\t\tCode:\t%d\n", icmph->code);
    printf("\t\tChecksum:\t0x%x\n", ntohs(icmph->checksum));
    printf("\t\tID:\t%d\n", ntohs(icmph->id));
    printf("\t\tSeq:\t%d\n", ntohs(icmph->seq));
}

// Function to swap the byte order of a 32-bit integer (big-endian to little-endian or vice versa)
bpf_u_int32 swap32(bpf_u_int32 val) {
    return ((val & 0xFF000000) >> 24) | // Move the highest byte to the lowest byte
           ((val & 0x00FF0000) >> 8)  | // Move the second highest byte to the second lowest byte
           ((val & 0x0000FF00) << 8)  | // Move the second lowest byte to the second highest byte
           ((val & 0x000000FF) << 24);  // Move the lowest byte to the highest byte
}

// Function to swap the byte order of a 16-bit integer (big-endian to little-endian or vice versa)
u_short swap16(u_short val) {
    return (val >> 8) | (val << 8); // Swap the high and low bytes
}

/* 
 * the output should be formatted identically to this command:
 *   tshark -T fields -e frame.time_epoch -e frame.cap_len -e frame.len -e eth.dst -e eth.src -e eth.type  -r ping.dmp
 */

unsigned short calculate_checksum(unsigned short *buf, int len) {
    unsigned long sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

void respond_to_icmp_echo_request(int writefd, struct pcap_pkthdr *pcap, eth_hdr *eth, struct ip_hdr *iph, struct icmp_hdr *icmph, int packet_len) {
    // Create buffers for the response
    struct pcap_pkthdr pph;
    struct eth_hdr eth_resp;
    struct ip_hdr ip_resp;
    struct icmp_hdr icmp_resp;

    // Prepare the pcap header for the response
    pph.ts_secs = pcap->ts_secs;
    pph.ts_usecs = pcap->ts_usecs;
    pph.caplen = packet_len; // Use the same length as the original packet
    pph.len = packet_len; // Use the same length as the original packet

    if(debug == 1) {
        print_pcap_packet_header(&pph);
    }

    // Prepare Ethernet header
    memcpy(eth_resp.dst, eth->src, 6); // Swap source and destination MAC addresses
    memcpy(eth_resp.src, eth->dst, 6);
    eth_resp.type = eth->type;

    // Prepare IP header
    ip_resp.ver_ihl = iph->ver_ihl;
    ip_resp.tos = iph->tos;
    ip_resp.len = htons(ntohs(iph->len)); // Same length as the original packet
    ip_resp.id = iph->id;
    ip_resp.frag_off = iph->frag_off;
    ip_resp.ttl = 64; // Set a default TTL
    ip_resp.proto = iph->proto;
    ip_resp.check = 0; // Checksum will be calculated later
    ip_resp.src = iph->dst; // Swap source and destination IP addresses
    ip_resp.dst = iph->src;

    // Calculate IP checksum
    ip_resp.check = calculate_checksum((unsigned short *)&ip_resp, sizeof(struct ip_hdr));

    // Prepare ICMP header
    icmp_resp.type = 0; // Echo Reply
    icmp_resp.code = 0;
    icmp_resp.checksum = 0;
    icmp_resp.id = icmph->id;
    icmp_resp.seq = icmph->seq;

    // Calculate ICMP data length
    int icmp_data_len = packet_len - sizeof(struct eth_hdr) - ((iph->ver_ihl & 0x0F) * 4) - sizeof(struct icmp_hdr);
    if (icmp_data_len < 0 || icmp_data_len > 1500) { // Validate ICMP data length
        fprintf(stderr, "Invalid ICMP data length: %d\n", icmp_data_len);
        return;
    }

    // Allocate memory for the ICMP packet (header + data)
    unsigned char *icmp_packet = (unsigned char *)malloc(sizeof(struct icmp_hdr) + icmp_data_len);
    if (!icmp_packet) {
        perror("malloc");
        return;
    }

    // Copy ICMP header and data into the packet
    unsigned char *icmp_data = (unsigned char *)icmph + sizeof(struct icmp_hdr);
    memcpy(icmp_packet, &icmp_resp, sizeof(struct icmp_hdr));
    memcpy(icmp_packet + sizeof(struct icmp_hdr), icmp_data, icmp_data_len);

    // Calculate the ICMP checksum
    icmp_resp.checksum = calculate_checksum((unsigned short *)icmp_packet, sizeof(struct icmp_hdr) + icmp_data_len);

    // Update the checksum in the ICMP packet
    memcpy(icmp_packet, &icmp_resp, sizeof(struct icmp_hdr));

    // Debugging: Print the calculated checksum
    if (debug == 1) {
        printf("Calculated ICMP Checksum: 0x%x\n", ntohs(icmp_resp.checksum));
    }

    // Prepare an array of iovec structures for the writev system call
    struct iovec iov[10];
    int v = 0;

    // Add the pcap header to the iovec array.
    iov[v].iov_base = &pph; // Pointer to the pcap header data.
    iov[v].iov_len = sizeof(struct pcap_pkthdr); // Size of the pcap header.
    ++v; // Move to the next iovec entry.

    // Add the Ethernet header to the iovec array
    iov[v].iov_base = &eth_resp;
    iov[v].iov_len = sizeof(struct eth_hdr);
    ++v;

    // Add the IP header to the iovec array
    iov[v].iov_base = &ip_resp;
    iov[v].iov_len = sizeof(struct ip_hdr);
    ++v;

    // Add the ICMP packet (header + data) to the iovec array
    iov[v].iov_base = icmp_packet;
    iov[v].iov_len = sizeof(struct icmp_hdr) + icmp_data_len;
    ++v;

    // Write the response
    int rval = writev(writefd, iov, v);
    if (rval < 0) {
        perror("writev");
    } else if (debug == 1) {
        printf("Responded to ICMP Echo Request with %d bytes\n", rval);
    }

    // Free the dynamically allocated buffer
    free(icmp_packet);
}

void respond_to_udp_echo_request(int writefd, struct pcap_pkthdr *pcap, eth_hdr *eth, struct ip_hdr *iph, struct udp_hdr *udph, int packet_len) {
    // Create buffers for the response
    struct pcap_pkthdr pph;
    struct eth_hdr eth_resp;
    struct ip_hdr ip_resp;
    struct udp_hdr udp_resp;

    // Calculate UDP data length
    int udp_data_len = ntohs(udph->len) - sizeof(struct udp_hdr);
    if (udp_data_len < 0 || udp_data_len > 1500) { // Validate UDP data length
        fprintf(stderr, "Invalid UDP data length: %d\n", udp_data_len);
        return;
    }

    // Prepare the pcap header for the response
    pph.ts_secs = pcap->ts_secs;
    pph.ts_usecs = pcap->ts_usecs;
    pph.caplen = sizeof(struct eth_hdr) + sizeof(struct ip_hdr) + sizeof(struct udp_hdr) + udp_data_len;
    pph.len = pph.caplen;

    if (debug == 1) {
        print_pcap_packet_header(&pph);
    }

    // Prepare Ethernet header
    memcpy(eth_resp.dst, eth->src, 6); // Swap source and destination MAC addresses
    memcpy(eth_resp.src, eth->dst, 6);
    eth_resp.type = htons(0x0800); // Set EtherType to IP (0x0800)

    // Prepare IP header
    ip_resp.ver_ihl = (4 << 4) | (sizeof(struct ip_hdr) / 4); // Version = 4, IHL = 5 (20 bytes)
    ip_resp.tos = iph->tos;
    ip_resp.len = htons(sizeof(struct ip_hdr) + sizeof(struct udp_hdr) + udp_data_len); // Total length = IP header + UDP header + data
    ip_resp.id = iph->id;
    ip_resp.frag_off = htons(0x4000); // Don't Fragment flag
    ip_resp.ttl = 64; // Set a default TTL
    ip_resp.proto = IPPROTO_UDP; // Protocol = UDP
    ip_resp.check = 0; // Checksum will be calculated later
    ip_resp.src = iph->dst; // Swap source and destination IP addresses
    ip_resp.dst = iph->src;

    // Calculate IP checksum
    ip_resp.check = calculate_checksum((unsigned short *)&ip_resp, sizeof(struct ip_hdr));

    // Prepare UDP header
    udp_resp.sport = udph->dport; // Swap source and destination ports
    udp_resp.dport = udph->sport;
    udp_resp.len = htons(sizeof(struct udp_hdr) + udp_data_len); // Length of UDP header + data
    udp_resp.csum = 0; // Checksum will be calculated later

    // Allocate memory for the UDP packet (header + data)
    unsigned char *udp_packet = (unsigned char *)malloc(sizeof(struct udp_hdr) + udp_data_len);
    if (!udp_packet) {
        perror("malloc");
        return;
    }

    // Copy UDP header and data into the packet
    unsigned char *udp_data = (unsigned char *)udph + sizeof(struct udp_hdr);
    memcpy(udp_packet, &udp_resp, sizeof(struct udp_hdr));
    memcpy(udp_packet + sizeof(struct udp_hdr), udp_data, udp_data_len);

    // Calculate the UDP checksum
    udp_resp.csum = calculate_checksum((unsigned short *)udp_packet, sizeof(struct udp_hdr) + udp_data_len);

    // Update the checksum in the UDP packet
    memcpy(udp_packet, &udp_resp, sizeof(struct udp_hdr));

    // Debugging: Print the calculated checksum
    if (debug == 1) {
        printf("Calculated UDP Checksum: 0x%x\n", ntohs(udp_resp.csum));
    }

    // Debugging: Print response packet details
    if (debug == 1) {
        printf("Response Packet Length: %d\n", pph.caplen);
        printf("Ethernet Header Length: %lu\n", sizeof(struct eth_hdr));
        printf("IP Header Length: %lu\n", sizeof(struct ip_hdr));
        printf("UDP Header Length: %lu\n", sizeof(struct udp_hdr));
        printf("UDP Payload Length: %d\n", udp_data_len);
    }

    // Debugging: Print UDP response details
    if (debug == 1) {
        printf("UDP Response:\n");
        printf("   |-Source Port      : %d\n", ntohs(udp_resp.sport));
        printf("   |-Destination Port : %d\n", ntohs(udp_resp.dport));
        printf("   |-Length           : %d\n", ntohs(udp_resp.len));
        printf("   |-Checksum         : 0x%x\n", ntohs(udp_resp.csum));
    }

    // Prepare an array of iovec structures for the writev system call
    struct iovec iov[10];
    int v = 0;

    // Add the Ethernet header to the iovec array
    iov[v].iov_base = &eth_resp;
    iov[v].iov_len = sizeof(struct eth_hdr);
    ++v;

    // Add the IP header to the iovec array
    iov[v].iov_base = &ip_resp;
    iov[v].iov_len = sizeof(struct ip_hdr);
    ++v;

    // Add the UDP packet (header + data) to the iovec array
    iov[v].iov_base = udp_packet;
    iov[v].iov_len = sizeof(struct udp_hdr) + udp_data_len;
    ++v;

    // Write the response
    int rval = writev(writefd, iov, v);
    if (rval < 0) {
        perror("writev");
    } else if (debug == 1) {
        printf("Responded to UDP Echo Request with %d bytes\n", rval);
    }

    // Free the dynamically allocated buffer
    free(udp_packet);
}

int main(int argc, char *argv[])
{
    struct pcap_file_header pfh;
    char *filename = NULL;

    if (argc < 2 || argc > 4) {
        fprintf(stdout, "Usage: %s [-d] [-n] filename\n", argv[0]);
        exit(99);
    }

    // Handle command line arguments and optional flags
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0) {
            debug = 1;
        } else if (strcmp(argv[i], "-n") == 0) {
            no_name_resolution = 1;
        } else {
            filename = argv[i];
        }
    }

    if (debug==2) printf("Trying to read from file '%s'\n", filename);

    /* now open the file (or if the filename is "-" make it read from standard input)*/
    int fd = open(filename, O_RDWR); // Open the file for both reading and writing
    if (fd < 0) {
        perror(filename);
        exit(1);
    }

    /* read the pcap_file_header at the beginning of the file, check it, then print as requested */
    bpf_u_int32 bytes_read = read(fd, &pfh, sizeof(pfh));
    if (bytes_read < sizeof(pfh)) {
        fprintf(stderr, "truncated pcap header: only %u bytes\n", bytes_read);
        exit(1);
    }

    // If the magic number is swapped, swap the byte order of the header fields
    if (pfh.magic == PCAP_SWAPPED_MAGIC) {
        swapped = 1;
        pfh.magic = swap32(pfh.magic);
        pfh.version_major = swap16(pfh.version_major);
        pfh.version_minor = swap16(pfh.version_minor);
        pfh.thiszone = swap32(pfh.thiszone);
        pfh.sigfigs = swap32(pfh.sigfigs);
        pfh.snaplen = swap32(pfh.snaplen);
        pfh.linktype = swap32(pfh.linktype);
    }

    if (pfh.magic != PCAP_MAGIC) {
        fprintf(stderr, "invalid magic number: 0x%08x\n", pfh.magic);
        exit(1);
    }

    if (pfh.version_major != PCAP_VERSION_MAJOR) {
        fprintf(stderr,"invalid pcap version: %d.%d\n", pfh.version_major, pfh.version_minor);
        exit(1);
    }

    if (pfh.version_minor != PCAP_VERSION_MINOR) {
        fprintf(stderr,"Wrong minor version\n");
        exit(1);
    }

    if (debug == 2) {
        printf("Magic: %08x\n", pfh.magic);
        printf("Version: %d.%d\n", pfh.version_major, pfh.version_minor);
        printf("Snaplen: %d\n", pfh.snaplen);
        printf("Linktype: %d\n", pfh.linktype);
    }

    printf("header magic: %08x\n", pfh.magic);
    printf("header version: %d %d\n", pfh.version_major, pfh.version_minor);
    printf("header linktype: %d\n", pfh.linktype);
    printf("\n");

    /* now read each packet in the file */
    while (1) {
        char packet_buffer[10000];

        /* read the pcap_packet_header, then print as requested */
        struct pcap_pkthdr pph;
        bytes_read = read(fd, &pph, sizeof(pph));
        if (bytes_read < sizeof(pph)) {
            if (bytes_read == 0) {
                usleep(10000); 
                continue;
            }
            fflush(stdout);
            fprintf(stderr, "truncated packet header: only %u bytes\n", bytes_read);
            exit(1);
        }

        if (swapped) {
            pph.ts_secs = swap32(pph.ts_secs);
            pph.ts_usecs = swap32(pph.ts_usecs);
            pph.caplen = swap32(pph.caplen);
            pph.len = swap32(pph.len);
        }

        printf("Raw caplen: %u\n", pph.caplen);
        if (swapped) {
            printf("Swapped caplen: %u\n", pph.caplen);
        }

        // Validate caplen
        if (pph.caplen > sizeof(packet_buffer)) {
            fprintf(stderr, "Captured packet length too large: %u\n", pph.caplen);
            continue;
        }

        if (pph.caplen > 1500) { // Ethernet MTU limit
            fprintf(stderr, "Invalid caplen for response packet: %u\n", pph.caplen);
            continue;
        }

        // Debugging output
        if (debug == 2) {
            printf("Packet header: ts_secs=%u, ts_usecs=%u, caplen=%u, len=%u\n",
                   pph.ts_secs, pph.ts_usecs, pph.caplen, pph.len);
        }

        if (pph.caplen > 10000) { // Ensure the captured length does not exceed the buffer size
            fprintf(stderr, "Captured packet length too large: %u\n", pph.caplen);
            continue;
        }

        /* then read the packet data that goes with it into a buffer (variable size) */
        bytes_read = read(fd, packet_buffer, pph.caplen);
        if (bytes_read < pph.caplen) {
            fflush(stdout);
            fprintf(stderr, "truncated packet: only %u bytes\n", bytes_read);
            exit(1);
        }

        /* now print the packet data as requested */
        // Cast the packet buffer to an Ethernet header structure
        struct eth_hdr *eth = (struct eth_hdr *) packet_buffer;

        // Cast the packet buffer to an IP header structure, offset by the size of the Ethernet header
        struct ip_hdr *iph = (struct ip_hdr *)(packet_buffer + sizeof(struct eth_hdr));

        // Cast the packet buffer to a TCP header structure, offset by the size of the Ethernet header and the IP header length
        struct tcp_hdr *tcph = (struct tcp_hdr *)(packet_buffer + sizeof(struct eth_hdr) + ((iph->ver_ihl & 0x0F) * 4));

        // Cast the packet buffer to a UDP header structure, offset by the size of the Ethernet header and the IP header length
        struct udp_hdr *udph = (struct udp_hdr *)(packet_buffer + sizeof(struct eth_hdr) + ((iph->ver_ihl & 0x0F) * 4));

        // Cast the packet buffer to an ARP header structure, offset by the size of the Ethernet header
        struct arp_hdr *arph = (struct arp_hdr *)(packet_buffer + sizeof(struct eth_hdr));

        printf("%10d.%06d000\t%u\t%u\t%02x:%02x:%02x:%02x:%02x:%02x\t%02x:%02x:%02x:%02x:%02x:%02x\t0x%04x\n",
               pph.ts_secs, pph.ts_usecs, pph.caplen, pph.len,
               eth->dst[0], eth->dst[1], eth->dst[2], eth->dst[3], eth->dst[4], eth->dst[5],
               eth->src[0], eth->src[1], eth->src[2], eth->src[3], eth->src[4], eth->src[5],
               ntohs(eth->type));

        if (ntohs(eth->type) == 0x0800) { // IP EtherType value is 0x0800
            print_ip_summary(iph);

            if (iph->proto == IPPROTO_ICMP) {
                struct icmp_hdr *icmph = (struct icmp_hdr *)(packet_buffer + sizeof(struct eth_hdr) + ((iph->ver_ihl & 0x0F) * 4));
                print_icmp_summary(icmph);

                if (icmph->type == 8 && icmph->code == 0) { // Echo Request
                    printf("ICMP Echo Request (Ping) detected\n");
                    respond_to_icmp_echo_request(fd, &pph, eth, iph, icmph, pph.caplen);
                } else if (icmph->type == 0 && icmph->code == 0) {
                    printf("ICMP Echo Reply detected\n");
                } else {
                    printf("Other ICMP packet detected (Type: %d, Code: %d)\n", icmph->type, icmph->code);
                }
            } else if (iph->proto == IPPROTO_TCP) {
                print_tcp_summary(tcph);
            } else if (iph->proto == IPPROTO_UDP) {
                print_udp_summary(udph);
                if (ntohs(udph->dport) == 7) { // Echo Protocol (port 7)
                    printf("UDP Echo Request detected\n");
                    respond_to_udp_echo_request(fd, &pph, eth, iph, udph, pph.caplen);
                } else {
                    printf("Other UDP packet detected (Source Port: %d, Destination Port: %d)\n", ntohs(udph->sport), ntohs(udph->dport));
                }
            }
        } else if (ntohs(eth->type) == 0x0806) { // ARP EtherType value is 0x0806
            print_arp_summary(arph);
        }

        if (debug == 2) {
            print_ethernet(eth);
            if (ntohs(eth->type) == 0x0800) { // IP
                print_ip(iph);
                if (iph->proto == IPPROTO_TCP) {
                    print_tcp_summary(tcph);
                } else if (iph->proto == IPPROTO_UDP) {
                    print_udp_summary(udph);
                }
            } else if (ntohs(eth->type) == 0x0806) { // ARP
                print_arp_summary(arph);
            }
        }
        printf("\n");
        fflush(stdout);
    }

    close(fd);
    return 0;
}

