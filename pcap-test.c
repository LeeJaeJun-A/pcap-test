#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>

#ifndef ETHERTYPE_IP
#define ETHER_ADDR_LEN 6
#endif
#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP 0x0800  /* IP protocol */
#endif

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
#if (LIBNET_LIL_ENDIAN)
    u_int8_t th_x2:4,         /* (unused) */
        th_off:4;        /* data offset */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t th_off:4,        /* data offset */
        th_x2:4;         /* (unused) */
#endif
    u_int8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR
#define TH_CWR    0x80
#endif
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};

struct libnet_ipv4_hdr
{
#if (LIBNET_LIL_ENDIAN)
    u_int8_t ip_hl:4,      /* header length */
        ip_v:4;         /* version */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t ip_v:4,       /* version */
        ip_hl:4;        /* header length */
#endif
    u_int8_t ip_tos;       /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

    printf("hihi");
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

        const struct libnet_ethernet_hdr *eth_hdr = (const struct libnet_ethernet_hdr*) packet;

        if(ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) continue;

        const struct libnet_ipv4_hdr *ip_hdr = (const struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));

        if(ip_hdr->ip_p != IPPROTO_TCP) continue;

        const u_char *ip_header = (const u_char *)ip_hdr;
        u_int8_t ip_header_length = (*ip_header & 0x0F) * 4;

        const struct libnet_tcp_hdr *tcp_hdr = (const struct libnet_tcp_hdr *)(packet + ip_header_length + sizeof(struct libnet_ethernet_hdr));

        printf("Source MAC: ");
        for(int i = 0; i < ETHER_ADDR_LEN; i++) {
            printf("%02x", eth_hdr->ether_shost[i]);
            if (i < ETHER_ADDR_LEN - 1)
                printf(":");
        }

        printf(" Destination MAC: ");
        for(int i = 0; i < ETHER_ADDR_LEN; i++) {
            printf("%02x", eth_hdr->ether_dhost[i]);
            if (i < ETHER_ADDR_LEN - 1)
                printf(":");
        }

        printf("\n");

        printf("Source IP: %s ", inet_ntoa(ip_hdr->ip_src));
        printf("Destination IP: %s", inet_ntoa(ip_hdr->ip_dst));

        printf("\n");

        printf("Source Port:%04x Destination Port: %04x ", ntohs(tcp_hdr->th_sport), ntohs(tcp_hdr->th_dport));
        printf("\n");

        const u_char *tcp_header = (const u_char *)tcp_hdr + 12; // offset 활용가능능
        u_int8_t tcp_header_length = ((*tcp_header >> 4) & 0x0F) * 4; // Option이 없을 때, IP헤더의 길이는 20bytes인데 4bit로 표현못하니까 나누기 4한 값을 저장하고 있음
	// *tcp_header >> 2;
        u_int16_t data_size = ntohs(ip_hdr->ip_len) - ip_header_length - tcp_header_length;

        if(data_size != 0){
            printf("Data: ");
            u_char *data = (u_char *)(packet + sizeof(struct libnet_ethernet_hdr) + ip_header_length + tcp_header_length);
            for(int i = 0; i < (data_size > 10 ? 10 : data_size); ++i){
                printf("%02x ",data[i]);
            }
        }

        printf("\n\n");
	}

	pcap_close(pcap);
}
