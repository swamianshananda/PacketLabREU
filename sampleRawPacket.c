#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <unistd.h>

typedef struct{
    	
    		uint8_t version_ihl;
    		uint8_t dscp_ecn;
    		uint16_t total_length;
    		uint16_t identification;
    		uint16_t flags_fragment_offset;
    		uint8_t ttl;
    		uint8_t protocol;
    		uint16_t checksum;
    		uint32_t source_ip;
    		uint32_t dest_ip;
    	
    	} ipv4header;
    	
typedef struct{
    		
    		uint16_t source_port;
    		uint16_t dest_port;
    		uint16_t length;
    		uint16_t checksum;
    	
    	} udpheader;
    	
typedef struct{

		uint8_t type;
		uint8_t code;
		uint16_t checksum;
		uint32_t rest;

	} icmp_header;

typedef struct{
    	
    		ipv4header ip;
    		udpheader udp;
    		uint8_t data[32];
    	
    	} measurement_packet;
    	
typedef struct{
    	
    		ipv4header ip;
    		udpheader udp;
    		uint8_t data[472];
    	
    	} load_packet;
    	
typedef struct{
		
		measurement_packet beg[30];
		load_packet mid[60];
		measurement_packet end[30];

	} rpt;
    	
    	
void calculate_checksum(uint16_t* ptr, int num_bytes, uint16_t* checksum_field);
    	
void calculate_checksum(uint16_t* ptr, int num_bytes, uint16_t* checksum_field){
	
	uint32_t sum = 0;
	
	while(num_bytes > 1){
	
		sum += *(ptr++);
		num_bytes-=2;
	
	}
	
	if(num_bytes > 0){
	
		sum+= *((uint8_t*) ptr);
	
	}
	
	while(sum>>16){
	
		sum = (sum & 0xffff) + (sum>>16);
	
	}
	
	*checksum_field = ~sum;

}

int main(){

	int s  = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
	
	if(s == -1){
		printf("Error on creating socket.\n");
		return 0;
	}
		
	
	struct sockaddr_in endpoint;
    	endpoint.sin_family = AF_INET;
    	endpoint.sin_port = htons(0);
    	endpoint.sin_addr.s_addr = htonl(0x08080808);
    	memset(endpoint.sin_zero, 0, sizeof(unsigned char)*8);
    	
    	int c = connect(s, (struct sockaddr*) &endpoint, sizeof(endpoint));
    	
    	if(c == -1){
		printf("Error on connecting.\n");
		return 0;
	}
    	
    	rpt sample;
    	
    	uint16_t id = 0;
    	
    	for(int i = 0; i<30; i++){
    	
    		sample.beg[i].ip.version_ihl = 0x45;
    		sample.beg[i].ip.dscp_ecn = 0x00;
    		sample.beg[i].ip.total_length = htons((uint16_t) sizeof(measurement_packet));
    		sample.beg[i].ip.identification = htons(id++);
    		sample.beg[i].ip.flags_fragment_offset = htons(0x0000);
    		sample.beg[i].ip.ttl = (uint8_t) i+1;
    		sample.beg[i].ip.protocol = 0x11;
    		sample.beg[i].ip.source_ip = 0;
    		sample.beg[i].ip.dest_ip = htonl(0x08080808);
    		sample.beg[i].ip.checksum = 0;
    		
    		calculate_checksum((uint16_t*) &(sample.beg[i].ip), 20, &(sample.beg[i].ip.checksum));
    		
    		sample.beg[i].udp.source_port = htons(6969);
    		sample.beg[i].udp.dest_port = 0;
    		sample.beg[i].udp.length = htons((uint16_t) (sizeof(measurement_packet) - sizeof(ipv4header)));
    		sample.beg[i].udp.checksum = 0;
    		
    	}
    	
    	for(int i = 0; i<60; i++){
    	
    		sample.mid[i].ip.version_ihl = 0x45;
    		sample.mid[i].ip.dscp_ecn = 0x00;
    		sample.mid[i].ip.total_length = htons((uint16_t) sizeof(load_packet));
    		sample.mid[i].ip.identification = htons(id++);
    		sample.mid[i].ip.flags_fragment_offset = htons(0x0000);
    		sample.mid[i].ip.ttl = 255;
    		sample.mid[i].ip.protocol = 0x11;
    		sample.mid[i].ip.source_ip = 0;
    		sample.mid[i].ip.dest_ip = htonl(0x08080808);
    		sample.mid[i].ip.checksum = 0;
    		
    		calculate_checksum((uint16_t*) &(sample.mid[i].ip), 20, &(sample.mid[i].ip.checksum));
    		
    		sample.mid[i].udp.source_port = htons(6969);
    		sample.mid[i].udp.dest_port = 0;
    		sample.mid[i].udp.length = htons((uint16_t) (sizeof(load_packet) - sizeof(ipv4header)));
    		sample.mid[i].udp.checksum = 0;
    		
    	}
    	
    	for(int i = 30; i>0; i--){
    	
    		sample.end[30-i].ip.version_ihl = 0x45;
    		sample.end[30-i].ip.dscp_ecn = 0x00;
    		sample.end[30-i].ip.total_length = htons((uint16_t) sizeof(measurement_packet));
    		sample.end[30-i].ip.identification = htons(id++);
    		sample.end[30-i].ip.flags_fragment_offset = htons(0x0000);
    		sample.end[30-i].ip.ttl = (uint8_t) i;
    		sample.end[30-i].ip.protocol = 0x11;
    		sample.end[30-i].ip.source_ip = 0;
    		sample.end[30-i].ip.dest_ip = htonl(0x08080808);
    		sample.end[30-i].ip.checksum = 0;
    		
    		calculate_checksum((uint16_t*) &(sample.end[30-i].ip), 20, &(sample.end[30-i].ip.checksum));
    		
    		sample.end[30-i].udp.source_port = htons(6969);
    		sample.end[30-i].udp.dest_port = 0;
    		sample.end[30-i].udp.length = htons((uint16_t) (sizeof(measurement_packet) - sizeof(ipv4header)));
    		sample.end[30-i].udp.checksum = 0;
    		
    	}
    	
    	int ss = send(s, &sample.beg[0], sizeof(sample.beg[0]), 0);
    	ss = send(s, &sample.beg[1], sizeof(sample.beg[1]), 0);
    	
    	if(ss == -1){
		printf("Error on sending.\n");
		perror("");
		return 0;
	}
    	
    	return 0;

}
