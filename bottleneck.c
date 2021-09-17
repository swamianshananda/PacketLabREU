#include "bottleneck.h"


int main(){

	struct sockaddr_in endpoint;
    	endpoint.sin_family = AF_INET;
    	endpoint.sin_port = htons(6969);
    	endpoint.sin_addr.s_addr = INADDR_ANY;
    	memset(endpoint.sin_zero, 0, sizeof(unsigned char)*8);
    	
    	
    	int socket = pktif_ep_accept((struct sockaddr*) &endpoint);
    	struct pktif* endpoint_obj = pktif_init(socket,(struct sockaddr*) &endpoint);
    	
    	struct sockaddr_in sa;  // IPv4
    	sa.sin_family = AF_INET;
    	sa.sin_port = htons(6969);
    	inet_pton(AF_INET, "72.36.89.111", &(sa.sin_addr));
    	memset(sa.sin_zero, 0, sizeof(unsigned char)*8);
    	
    	uint32_t sourceIP = 0;
    	uint32_t destIP = sa.sin_addr.s_addr;
    	
    	uint16_t sourcePort = htons(6969);
    	uint16_t destPort = sa.sin_port;
    	
    	
    	pktif_connect_sync(endpoint_obj, 0,0x04,0, (struct sockaddr*) &sa, 0xFFFF, NULL);
    	
    	printf("Connected\n");
    	
    	rpt sample;
    	
    	uint16_t id = 0;
    	
    	
    	
    	for(int i = 0; i<NUM_HOPS; i++){
    		
    		constructUDPMeasurementPacket(&(sample.beg[i]), htons(id++), (uint8_t) i+1, sourceIP, destIP, sourcePort, destPort);
    		
    	}
    	
    	for(int i = 0; i<NUM_LOAD; i++){
    		
    		constructUDPLoadPacket(&(sample.mid[i]), htons(id++), sourceIP, destIP, sourcePort, destPort);
    		
    	}
    	
    	for(int i = NUM_HOPS; i>0; i--){
    		
    		constructUDPMeasurementPacket(&(sample.end[NUM_HOPS-i]), htons(id++), (uint8_t) i, sourceIP, destIP, sourcePort, destPort);
    		
    	}
    	
    	bpf_opcode filter[] = {
    	
    		{ htons(0x30), 0, 0, htonl(0x00000000) },
		{ htons(0x15), 0, 7, htonl(0x00000045) },
		{ htons(0x30), 0, 0, htonl(0x00000009) },
		{ htons(0x15), 0, 5, htonl(0x00000001) },
		{ htons(0x30), 0, 0, htonl(0x00000014) },
		{ htons(0x15), 0, 3, htonl(0x0000000b) },
		{ htons(0x30), 0, 0, htonl(0x00000015) },
		{ htons(0x15), 0, 1, htonl(0x00000000) },
		{ htons(0x6), 0, 0, htonl(0xffffffff) },
		{ htons(0x6), 0, 0, htonl(0x00000000) },

    	};
    	
    	int rv = pktif_ncap_sync(endpoint_obj, PKTLAB_TIME_MAX, filter, sizeof(filter));
   	printf("ncap status: %d\n", rv);
    	assert(rv == 0);
    	
    	
    	
     	location_interval locations[NUM_HOPS];
    	
    	memset(locations, 0, sizeof(location_interval)*NUM_HOPS);
    	
    	uint8_t recv_packet[576];
    	
    	uint32_t* src_ptr = (uint32_t*) &(recv_packet[12]);
    	
    	pktlab_time_t recv;
    	
    	uint32_t source;
    	
    	int recv_bytes = 0;
    	
    	int set = PKTIF_SEL_READ;
    	
//    	for(int iteration = 0; iteration < NUM_ITERATIONS; iteration ++){

		int act_hops = 0;
    	
    		int numb = 0;
    	
	    	pktlab_time_t offset;
	    	
	    	pktif_mread_systime_sync(endpoint_obj, &offset);
	    	
	    	for(int i = 0; i<NUM_HOPS; i++){
	    	
	    		numb+=pktif_send_sync(endpoint_obj, 0, &sample.beg[i], sizeof(sample.beg[i]), 1000000000 +offset, i, 0x04, NULL);
	    	
	    	}
	    	
	    	for(int i = 0; i<NUM_LOAD; i++){
	    	
	    		numb+=pktif_send_sync(endpoint_obj, 0, &sample.mid[i], sizeof(sample.mid[i]), 1000000000+offset, i+NUM_HOPS, 0x04, NULL);
	    	
	    	}
	    	
	    	for(int i = 0; i<NUM_HOPS; i++){
	    	
	    		numb+=pktif_send_sync(endpoint_obj, 0, &sample.end[i], sizeof(sample.end[i]),1000000000+offset, i+NUM_HOPS+NUM_LOAD, 0x04, NULL);
	    	
	    	}
	    	
//	    	printf("Iteration: %d\nSent %d bytes\n", iteration,numb);
	    	
	    	
	    	
	    	printf("Packet scheduled to be sent.\n");
	    	
	    	sleep(3);
	    	
	    	printf("Awakened.\n");
	    	
	    	for(int j = 0; j < 2*NUM_HOPS; j++){
	    	
	    	
	    		struct bar_param bar = {.barrier = 1, .param = NULL};
			pktif_cb_t msg_cb = {.fn = &recv_cb, .param = &bar};
			pktif_npoll(endpoint_obj, pktlab_time_now() + pktlab_time_sec(1), &msg_cb);
	    	
	    		while ((bar.barrier)) {
	    		
	    			fd_set readfds;
				FD_ZERO(&readfds);
				int nfds = pktif_prepare_select(endpoint_obj, set, 0, &readfds, NULL, NULL, NULL);
				nfds = select(nfds, &readfds, NULL, NULL, NULL);
				pktif_process_select(endpoint_obj, set, &nfds, &readfds, NULL, NULL, NULL);
	    		
	    		}
	    		
	    	
	    		
	    		
	    		
			
			recv_bytes = pktif_recv_async(endpoint_obj, 0, recv_packet, sizeof(recv_packet), &recv);
	    	
	    		source = ntohl(*src_ptr);
	    	
			if(recv_bytes){
				for(int i = 0; i < NUM_HOPS; i++){	
		    			if(locations[i].address == 0){  			
		    				locations[i].address = source;
		    				locations[i].begin_time = recv;
		    				act_hops++;	   				
		    				break;
		    			}
		    			
		    			else if (locations[i].begin_time == 0 && locations[i].address == source){	
		    				locations[i].begin_time = recv;
		    				break;	
		    			}
		    			
		    			else if (locations[i].end_time == 0 && locations[i].address == source){	
		    				locations[i].end_time = recv;
		    				locations[i].gap_time = locations[i].end_time - locations[i].begin_time;
		    				locations[i].gap_m_time = locations[i].gap_time;
		    				locations[i].begin_time = 0;
		    				locations[i].end_time = 0;
		    				break;	
		    			}
	    			}
			}
	    	}
	    	
	    	printf("Packets recieved.\n");
	    	
	    	
	    	for(int i = 1; i<act_hops-1; i++){
	    	
	    		if(locations[i].gap_time < locations[i-1].gap_time && locations[i].gap_time < locations[i+1].gap_time){
	    		
	    			unsigned long diff1 = locations[i-1].gap_time - locations[i].gap_time;
	    			unsigned long diff2 = locations[i+1].gap_time - locations[i].gap_time;
	    			if(diff1 > diff2)
	    				locations[i].gap_m_time = locations[i+1].gap_time;
	    			else
	    				locations[i].gap_m_time = locations[i-1].gap_time;
	    		
	    		}
	    		
	    		else if(locations[i].gap_time > locations[i-1].gap_time && locations[i].gap_time > locations[i+1].gap_time){
	    		
	    			unsigned long diff1 = locations[i].gap_time - locations[i-1].gap_time;
	    			unsigned long diff2 = locations[i].gap_time - locations[i+1].gap_time;
	    			if(diff1 > diff2)
	    				locations[i].gap_m_time = locations[i+1].gap_time;
	    			else
	    				locations[i].gap_m_time = locations[i-1].gap_time;
	    		
	    		}
	    			
	    	
	    	}
	    	
	    	unsigned long avg[act_hops][act_hops];
	    	unsigned long dist_sum[act_hops][act_hops];
	    	unsigned long fs[act_hops][act_hops][act_hops];
	    	unsigned long ls[act_hops][act_hops][act_hops];
	    	unsigned long opt[act_hops][act_hops][act_hops];
	    	bool sp[act_hops][act_hops][act_hops][act_hops];
	    	
	    	
	    
	    	
	    	for(int j = 0; j<act_hops; j++){
	    		for(int i = 0; i<=j; i++){
	    			unsigned long sum = 0;
	    			for(int k = i; k<=j; k++){    			
	    				sum += locations[k].gap_m_time;
	    			}
	    			avg[i][j] = sum/(j-i+1);
	    		}
	    	}
	    	
	    	for(int j = 0; j<act_hops; j++){
	    		for(int i = 0; i<=j; i++){
	    			unsigned long sum = 0;
	    			for(int k = i; k<=j; k++){	
	    				sum += abs(avg[i][j]-locations[k].gap_m_time);
	    			}
	    			dist_sum[i][j] = sum;
	    		}
	    	}
	    	
	    	for(int j = 0; j<act_hops; j++){
	    		for(int i = 0; i<=j; i++){
	    			fs[i][j][0] = avg[i][j];
	    			ls[i][j][0] = avg[i][j];
	    			opt[i][j][0] = dist_sum[i][j];
	    		}
	    	}
	    	
	    	for(int l = 1; l<act_hops; l++){
	    		for(int j = 0; j<act_hops; j++){
	    			for(int i = 0; i<=j; i++){
	    			
	    				fs[i][j][l] = fs[i][j][l-1];
	    				ls[i][j][l] = ls[i][j][l-1];
	    				opt[i][j][l] = opt[i][j][l-1];
	    				
	    				for(int n = 0; n<act_hops; n++){
	    					sp[i][j][l][n] = false;	
	    					
	    				}
	    				
	    				for(int m = 0; m<l; m++){
	    					for(int k = i; k<j; k++){
	    					
	    						if((abs(ls[i][k][m] - fs[k+1][j][l-m-1]) > 100000) && (opt[i][k][m]+opt[k+1][j][l-m-1] < opt[i][j][l])){
	    						
	    							opt[i][j][l] = opt[i][k][m] + opt[k+1][j][l-m-1];
	    							ls[i][j][l] = ls[k+1][j][l-m-1];
	    							fs[i][j][l] = fs[i][k][m];
	    							sp[i][j][l][k] = true;
	    						
	    						}
	    					}
	    				}
	    			
	    			}
	    		}
	    	}
	    	
	    	
	    	
	    	
	    	
	    	
	    	
	    	
    	
//    	}
    	
    	
    	char address_string[20];
    	
    	for(int i = 0; i < act_hops; i++){
    		source = htonl(locations[i].address);
	    	inet_ntop(AF_INET, &(source), address_string, sizeof(address_string));
    		printf("location: %s had gap of %lu ns and modified time of %lu ns.\n", address_string, locations[i].gap_time, locations[i].gap_m_time);	
	    	if(sp[0][act_hops-1][act_hops-1][i]){				
	    		printf("potential chokepoint at location: %s \n", address_string);
	    	}

    	}
    	
    	
    	/*
    	for(int i = 0; i< recv_bytes; i++){
    		if (i%4 == 0)
    			printf("\n");
    		printf("%.2x", recv_packet[i]);
    		
    	}
    	
    	
    	printf("\nPacket printed.\n");
    	
    	*/
    	
    	pktif_close_sync(endpoint_obj, 0);
    	
    	
    	printf("End.\n");
	return 0;

}


