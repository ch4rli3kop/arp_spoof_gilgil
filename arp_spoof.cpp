#include <iostream>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include <unistd.h>
#include <pcap.h>

using namespace std;

struct ethernet_header{
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint8_t type[2];
};

struct arp_header{
    uint8_t hd_type[2];
    uint8_t pr_type[2];
    uint8_t hd_len;
    uint8_t pr_len;
    uint8_t opcode[2];
    uint8_t smac[6];
    uint8_t sip[4];
    uint8_t tmac[6];
    uint8_t tip[4];
};

struct packet{
    struct ethernet_header eth;
    struct arp_header arp;
};


    // host -> me!
    // sender -> victim
    // target -> generally router
struct session{
    uint8_t sip[4];
    uint8_t smac[6];
    uint8_t tip[4];
    uint8_t tmac[6];	
};

void get_mymac(char* mymac, char* iface){
   	int fd;
	
	struct ifreq ifr;
	char *mac;
	
	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy((char *)ifr.ifr_name , (const char *)iface , IFNAMSIZ-1);

	ioctl(fd, SIOCGIFHWADDR, &ifr);

	close(fd);
	
	mac = (char *)ifr.ifr_hwaddr.sa_data;
	for(int i=0; i<6; i++) mymac[i] = mac[i];
}

bool check_arp(const u_char* packet, uint8_t* mymac){
    struct ethernet_header eth;
    int type;

    memcpy(&eth, packet, 14);
    type = (eth.type[0]<<8 | eth.type[1]);
    if(type == 0x0806) {
	if(!memcmp(eth.dst_mac, mymac, 6)) return true;
    }
    return false;
}

void extract_mac(const u_char* packet, uint8_t* tmac){
    struct arp_header arp;
    memcpy(&arp, &packet[14], 28);
    for (int i=0; i<6; i++) tmac[i] = arp.smac[i];
}

void get_mac(pcap_t* handle, uint8_t* smac, uint8_t* tmac, uint8_t* tip){
    struct packet buf;

    // compose ethernet header
    memcpy(buf.eth.dst_mac, "\xff\xff\xff\xff\xff\xff", 6);
    memcpy(buf.eth.src_mac, smac, 6);
    memcpy(buf.eth.type, "\x08\x06", 2);
    // compose arp header
    memcpy(buf.arp.hd_type, "\x00\x01", 2);
    memcpy(buf.arp.pr_type, "\x08\x00", 2);
    buf.arp.hd_len = '\x06';
    buf.arp.pr_len = '\x04';
    memcpy(buf.arp.opcode, "\x00\x01", 2);  // request
    memcpy(buf.arp.smac, smac, 6);
    memcpy(buf.arp.sip, "\xde\xad\xbe\xef", 4);
    memcpy(buf.arp.tmac, "\x00\x00\x00\x00\x00\x00", 6);
    memcpy(buf.arp.tip, tip, 4);
      
    if(!pcap_sendpacket(handle, (const u_char*)&buf, 60)) 
        printf("send packet....\n");
    else
        fprintf(stderr, "send packet error!\n");
        
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        printf("%u bytes captured\n", header->caplen);
        if(check_arp(packet, smac)){
            extract_mac(packet, tmac);
            break;
        }
    }
}

void print_mac(uint8_t* mac){
    printf("MAC => %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/*
void send_fake_packet(pcap_t* handle, uint8_t* mymac, uint8_t* smac, uint8_t* sip, uint8_t* tip){
    struct packet buf;
   
    // compose ethernet header
    memcpy(buf.eth.dst_mac, smac, 6);
    memcpy(buf.eth.src_mac, mymac, 6);
    memcpy(buf.eth.type, "\x08\x06", 2);
    // compose arp header
    memcpy(buf.arp.hd_type, "\x00\x01", 2);
    memcpy(buf.arp.pr_type, "\x08\x00", 2);
    buf.arp.hd_len = '\x06';
    buf.arp.pr_len = '\x04';
    memcpy(buf.arp.opcode, "\x00\x02", 2); // reply
    memcpy(buf.arp.smac, mymac, 6);
    memcpy(buf.arp.sip, tip, 4);
    memcpy(buf.arp.tmac, smac, 6);
    memcpy(buf.arp.tip, sip, 4);
   
    int i=1; 
    while(true){
        if(!pcap_sendpacket(handle, (uint8_t)buf, 60)){ 
            printf("[%d] send packet....\n", i);
            i++;
        } else {
            fprintf(stderr, "send packet error!\n");
        }
    }

}
*/

int main(int argc, char* argv[]){

    if(argc < 4){
        printf("usage : ./send_arp [interface] [sender_ip] [target_ip]....\n");
        return -1;
    }

    if( (argc-2)%2 != 0){
        printf("check out the pairs of sender_ip - target_ip!\n");
        return -1;
    }

    uint8_t mymac[6]; // host mac address
    get_mymac((char*)mymac, argv[1]); // get host mac address
    printf("[+] my ");
    print_mac(mymac);

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL){
        fprintf(stderr, "pcap_open_live error!\n");
        return -1;    
    }
   
    // compose session
    int session_num = (argc-2)/2;
    session* sessions = new session[session_num];

    for (int i=0; i<session_num; i++){
        inet_aton(argv[2+2*i], (in_addr*)sessions[i].sip); // sender ip
        inet_aton(argv[3+2*i], (in_addr*)sessions[i].tip); // target ip
        get_mac(handle, mymac, sessions[i].smac, sessions[i].sip);
        printf("[%d] sender ", i);
        print_mac(sessions[i].smac);
        get_mac(handle, mymac, sessions[i].tmac, sessions[i].tip);
        printf("[%d] target ", i);
        print_mac(sessions[i].tmac);        
    }
  
    // send fake reply and initialize target arp cache table
    // reply sender's packet to gateway
    // 
      
 
    return 0;
}
