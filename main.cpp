#include <stdlib.h>
#include <pcap/pcap.h>
#include <iostream>
#include <stdio.h>
#include <cstring>
#include <vector>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <iomanip>
#include <time.h>
#include <unistd.h>
#define SNAP_LEN 1518
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6
#define ETHERTYPE_IP 0x0800   // IP
#define ETHERTYPE_ARP 0x0806  // Address resolution protocol
#define ETHERTYPE_RARP 0x8035 // Reverse ARP
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)
using namespace std;

typedef u_int tcp_seq;
/*Ethernet header*/

typedef struct ether_hdr
{
    u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
    u_short ether_type;

} ETHER_HDR;

typedef struct ip_header
{
    u_char ip_vhl;
    u_char ip_tos;
    u_short ip_len; /* total length */
    u_short ip_id;
    u_short ip_off;
#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff
    u_char ip_ttl;
    u_char ip_p;
    u_short ip_sum;
    struct in_addr ip_src, ip_dst; /* source and dest address */

} IP_HEADER;

typedef struct tcp_header
{
    u_short th_sport; /* source port */
    u_short th_dport; /* destination port */
    tcp_seq th_seq;
    tcp_seq th_ack;
    u_char th_offx2;
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
} TCP_HEADER;

// udp header
typedef struct udp_header
{
    u_short uh_sport; /* source port */
    u_short uh_dport; /* destination port */
    u_short uh_ulen;  /* udp length */
    u_short uh_sum;
#define SIZE_UDP 8 //size of UDP header is 8 bytes
} UDP_HEADER;

void pcap_handler_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

const u_char *datacheck;

int main(int argc, char **argv)
{

    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    std::string device, file, filter, expression;
    int c;
    while ((c = getopt(argc, argv, "d:f:s:")) != -1)

        switch (c)
        {
        case 'd':
            device = std::string(optarg);
            break;
        case 'f':
            file = std::string(optarg);
            break;
        case 's':
            filter = std::string(optarg);
            break;
        default:
            exit(0);
        }

    for (int index = optind; index < argc; index++)
    {
        expression += " ";
        expression += std::string(argv[index]);
    }

    if (file != "")
    {
        /* pcap_open_offline() and pcap_open_offline_with_tstamp_precision() are called to open a ``savefile'' for reading.*/

        handle = pcap_open_offline(file.c_str(), errbuf);
        if (handle == NULL)
        {
            std::cerr << errbuf << std::endl;

            return (2);
        }
    }
    else
    {
        if (device != "")
        {
            dev = new char[sizeof(device.length() + 1)];
            std::strcpy(dev, device.c_str());
        }

        /*pcap_lookupnet() is used to determine the IPv4 network number and mask associated with the network device device.
          Both netp and maskp are bpf_u_int32 pointers.  */

        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
        {
            std::cerr << "Can't get netmask in device: " << dev << std::endl;
            net = 0;
            mask = 0;
        }

        /*pcap_open_live() is used to obtain a packet capture handle to look at packets on the network*/
        handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
        if (handle == NULL)
        {
            std::cerr << errbuf << std::endl;
            return -1;
        }
    }

    if (pcap_datalink(handle) != DLT_EN10MB)
    {
        std::cerr << " is not an Ethernet" << std::endl;
        exit(EXIT_FAILURE);
    }

    if (expression != "")
    {

        /*pcap_compile() is used to compile the string str into a filter program.*/
        if (pcap_compile(handle, &fp, expression.c_str(), 0, net) == -1)
        {
            std::cerr << pcap_geterr(handle) << std::endl;
            return (2);
        }

        /*pcap_setfilter() is used to specify a filter program.
         fp is a pointer to a bpf_program struct, usually the result of a call to pcap_compile(3PCAP). */
        if (pcap_setfilter(handle, &fp) == -1)
        {
            std::cerr << pcap_geterr(handle) << std::endl;
            return (2);
        }
    }

    if (filter != "")
    {

        pcap_loop(handle, 0, pcap_handler_callback, (u_char *)filter.c_str());
    }

    else
        pcap_loop(handle, 0, pcap_handler_callback, NULL);

    pcap_close(handle);
    return (0);

    pcap_close(handle);
    return 0;
}

void pcap_handler_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

    ETHER_HDR *ether_hdr;
    IP_HEADER *ip_hdr;
    TCP_HEADER *tcp_hdr;
    UDP_HEADER *udp_hdr;

    u_char *payload;
    int size_ip;
    int size_protocol;
    int size_payload;
    bool validPacket = false;
    char buffer[80];
    // struct tm *timeinfo;
    u_char *ptr;
    int i;

    ether_hdr = (ETHER_HDR *)packet; //typecasting packet
    //those structures define the headers that appear in the data for the packet

    if (ntohs(ether_hdr->ether_type) == ETHERTYPE_IP) // 0x0800 Internet Protocol version 4 (IPv4)
    {

        ip_hdr = (IP_HEADER *)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip_hdr) * 4;

        if (size_ip < 20)
        {
            std::cout << "Invalid IP header length: " << size_ip << std::endl;
        }

        /*

        https://www.tcpdump.org/pcap.html

        The u_char pointer is really just a variable containing an address in memory.
        That's what a pointer is; it points to a location in memory.

        For the sake of simplicity, we'll say that the address this pointer is set to is the value X.
        Well, if our three structures are just sitting in line, the first of them (sniff_ethernet)
        being located in memory at the address X,
        then we can easily find the address of the structure after it; that address is X plus the length of the Ethernet header,
        which is 14, or SIZE_ETHERNET.

        */
        std::string protocolName;
        auto srcPort = -1;
        auto destPort = -1;

        switch (ip_hdr->ip_p)
        {
        case IPPROTO_TCP:
            protocolName = "TCP";
            tcp_hdr = (TCP_HEADER *)(packet + SIZE_ETHERNET + size_ip);
            size_protocol = TH_OFF(tcp_hdr) * 4;
            if (size_protocol < 20)
            {
                std::cout << "Invalid IP header length: " << size_protocol << std::endl;
                return;
            }
            srcPort = ntohs(tcp_hdr->th_sport);
            destPort = ntohs(tcp_hdr->th_dport);
            payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_protocol);
            size_payload = ntohs(ip_hdr->ip_len) - (size_ip + size_protocol);
            break;

        case IPPROTO_UDP:
            protocolName = "UDP";
            udp_hdr = (UDP_HEADER *)(packet + SIZE_ETHERNET + size_ip);
            size_protocol = SIZE_UDP;
            srcPort = ntohs(udp_hdr->uh_sport);
            destPort = ntohs(udp_hdr->uh_dport);
            payload = (u_char *)(packet + SIZE_ETHERNET + size_ip);
            size_payload = ntohs(ip_hdr->ip_len) - (size_ip + size_protocol);
            break;

        case IPPROTO_ICMP:
            protocolName = "ICMP";
            size_protocol = 8; //size of ICMP header is 8 bytes
            payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_protocol);
            size_payload = ntohs(ip_hdr->ip_len) - (size_ip + size_protocol);
            break;
        default:
            protocolName = "Unknown Protocol";
            payload = (u_char *)(packet + SIZE_ETHERNET + size_ip);
            size_payload = ntohs(ip_hdr->ip_len) - size_ip;
            break;
        }

        /* payload içerisinde harf rakam olmayan karakterlerin yerine . karakteri atanır*/

        char *payloadCopy = (char *)malloc(size_payload);
        char *payloadCopyPtr = payloadCopy;
        char c;
        memcpy(payloadCopy, payload, size_payload);
        for (i = 0; i < size_payload; i++)
        {
            if (!isprint(*payloadCopyPtr))
            {
                c = '.';
                *payloadCopyPtr = c;
            }
            *payloadCopyPtr++;
        }

        if (args == NULL)
        {
            validPacket = true;
        }

        /*girilen filter ifadesi ile eşleşen paketler işleme alınır*/
        else if (strstr((char *)payloadCopy, (char *)args))
        {
            validPacket = true;
        }

        if (validPacket == true)
        {

            time_t now = time(0);

            // convert now to string form
            char *dt = ctime(&now);
            std::cout << dt;
            std::cout << "=======================================================================================" << std::endl;

            std::cout << "Ethernet type hex:" << std::hex << ntohs(ether_hdr->ether_type) << " is an IP Packet - ";

            std::cout << "len: " << static_cast<double>(header->len) << std::endl;

            ptr = ether_hdr->ether_shost;
            i = ETHER_ADDR_LEN;

            std::cout << "Ethernet src: ";
            do
            {
                auto result = (i == ETHER_ADDR_LEN) ? " " : ":";
                std::cout << result << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(*ptr++);

            } while (--i > 0);

            std::cout << " ----> ";

            ptr = ether_hdr->ether_dhost;
            i = ETHER_ADDR_LEN;
            std::cout << "Ethernet dst: ";
            do
            {
                auto result = (i == ETHER_ADDR_LEN) ? " " : ":";
                std::cout << result << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(*ptr++);

            } while (--i > 0);

            std::cout << std::endl;

            std::cout << "ip src: " << inet_ntoa(ip_hdr->ip_src);

            std::cout << " src port: " << static_cast<double>(srcPort);

            std::cout << " ----- ";

            std::cout << "ip dst: " << inet_ntoa(ip_hdr->ip_dst);

            if (destPort != -1)
                std::cout << " dest port: " << static_cast<double>(srcPort);

            std::cout << std::endl;

            std::cout << "Protocol: " << protocolName << std::endl;

            std::cout << "=======================================================================================" << std::endl;
        }
    }
}

// enp0s3
// enp0s25
// eth0
