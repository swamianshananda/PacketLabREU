#include "../pktlab-libpktlab/include/pktif.h"
#include "../pktlab-libpktlab/src/pktif/callbackmgr.h"
#include "../pktlab-libpktlab/src/pktif/struct_pktif.h"
#include "../pktlab-libpktlab/src/pktif/util/barrier.h"
#include "../pktlab-libpktlab/src/pktif/util/debug.h"
#include "../pktlab-libpktlab/src/pktif/util/util.h" //change this and the above based on location of pktlab library
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
#include <assert.h>
#include <time.h>
#define NUM_HOPS 10
#define NUM_LOAD 100
#define NUM_TRAINS 10
#define NUM_ITERATIONS 10

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
    	
    		ipv4header ip;
    		udpheader udp;
//    		uint8_t data[32];
    	
    	} measurement_packet;
    	
typedef struct{
    	
    		ipv4header ip;
    		udpheader udp;
    		uint8_t data[1456];
    	
    	} load_packet;
    	
typedef struct{
		
		measurement_packet beg[NUM_HOPS];
		load_packet mid[NUM_LOAD];
		measurement_packet end[NUM_HOPS];

	} rpt;
	
typedef struct{

	uint16_t code;
	uint8_t jt;
	uint8_t jf;
	uint32_t k;

	} bpf_opcode;
	
typedef struct{

	uint32_t address;
	unsigned long begin_time;
	unsigned long end_time;
	unsigned long gap_time;
	unsigned long gap_m_time;
	
	} location_interval;

	
	
void calculate_checksum(uint16_t* ptr, int num_bytes, uint16_t* checksum_field);

void constructUDPMeasurementPacket(measurement_packet* pkt, uint16_t id, uint8_t ttl, uint32_t sourceIP, uint32_t destIP, uint16_t sourcePort, uint16_t destPort);

void constructUDPLoadPacket(load_packet* pkt, uint16_t id, uint32_t sourceIP, uint32_t destIP, uint16_t sourcePort, uint16_t destPort);

static int recv_cb(struct pktif *pktif, struct pktlab_message *msg, void *param);

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

void constructUDPMeasurementPacket(measurement_packet* pkt, uint16_t id, uint8_t ttl, uint32_t sourceIP, uint32_t destIP, uint16_t sourcePort, uint16_t destPort){

	pkt->ip.version_ihl = 0x45;
    	pkt->ip.dscp_ecn = 0x00;
    	pkt->ip.total_length = htons((uint16_t) sizeof(measurement_packet));
    	pkt->ip.identification = id;
    	pkt->ip.flags_fragment_offset = htons(0x4000);
    	pkt->ip.ttl = ttl;
    	pkt->ip.protocol = 0x11;
    	pkt->ip.source_ip = sourceIP;
    	pkt->ip.dest_ip = destIP;
    	pkt->ip.checksum = 0;
    	
    	calculate_checksum((uint16_t*) &(pkt->ip), 20, &(pkt->ip.checksum));
    	
   	pkt->udp.source_port = sourcePort;
    	pkt->udp.dest_port = destPort;
    	pkt->udp.length = htons((uint16_t) (sizeof(measurement_packet) - sizeof(ipv4header)));
    	pkt->udp.checksum = 0;

}

void constructUDPLoadPacket(load_packet* pkt, uint16_t id, uint32_t sourceIP, uint32_t destIP, uint16_t sourcePort, uint16_t destPort){

	pkt->ip.version_ihl = 0x45;
    	pkt->ip.dscp_ecn = 0x00;
    	pkt->ip.total_length = htons((uint16_t) sizeof(load_packet));
    	pkt->ip.identification = id;
    	pkt->ip.flags_fragment_offset = htons(0x4000);
    	pkt->ip.ttl = 255;
    	pkt->ip.protocol = 0x11;
    	pkt->ip.source_ip = sourceIP;
    	pkt->ip.dest_ip = destIP;
    	pkt->ip.checksum = 0;
    	
    	calculate_checksum((uint16_t*) &(pkt->ip), 20, &(pkt->ip.checksum));
    	
   	pkt->udp.source_port = sourcePort;
    	pkt->udp.dest_port = destPort;
    	pkt->udp.length = htons((uint16_t) (sizeof(load_packet) - sizeof(ipv4header)));
    	pkt->udp.checksum = 0;

}

static int recv_cb(struct pktif *pktif, struct pktlab_message *msg,
                   void *param) {
    if (msg->type != PKTLAB_NSTAT_MESSAGE)
        warn("recv_cb called with different msg type");
    struct bar_param *bar_param = param;
    bar_param->barrier = 0;
    // update socket status
    const uint8_t *ptr;
    for (int i = 0; i < msg->nstat.len; i += PKTLAB_STATLIST_SIZE) {
        ptr = msg->nstat.ptr + i;
        pktif->skt_state[pktlab_get8(ptr)] = pktlab_get8(ptr + 1);
    }
    return 0;
}


