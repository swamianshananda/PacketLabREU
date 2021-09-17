#include "../pktlab-libpktlab/include/pktif.h"
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

int main(int argc, char** argv){

    if(argc !=2){
        printf("Enter one website.\n");
        return 0;
    }

    struct sockaddr_in endpoint;
    endpoint.sin_family = AF_INET;
    endpoint.sin_port = htons(6969);
    endpoint.sin_addr.s_addr = INADDR_ANY;
    memset(endpoint.sin_zero, 0, sizeof(unsigned char)*8);

    int len = strlen(argv[1]);
    char request[120+len], website[len],reception[40960];
    findHTTPRequestString(argv[1], request, website);

    int status;
    struct addrinfo template, *remote;
    pktlab_time_t send, recv;

    memset(&template, 0, sizeof(template)); // make sure the struct is empty
    template.ai_family = AF_UNSPEC;     // don't care IPv4 or IPv6
    template.ai_socktype = SOCK_STREAM; // TCP stream sockets

    if ((status = getaddrinfo(website, "http", &template, &remote)) != 0) {
        printf("getaddrinfo error: %s\n", gai_strerror(status));
        freeaddrinfo(remote);
        return 0;
    }

    int socket = pktif_ep_accept((struct sockaddr*) &endpoint);

    struct pktif* endpoint_obj = pktif_init(socket,(struct sockaddr*) &endpoint);
    
    pktif_connect_sync(endpoint_obj, 1,0x0c,0, remote->ai_addr, 0x1000, NULL);

    pktif_send_sync(endpoint_obj, 1, request, 120 + len,0, 0, 0x0c, NULL);
    
    while(1){   
    	int num = pktif_recv_sync(endpoint_obj, 1, reception, 40959, &recv);
    	if(num <= 0){
    		break;
    	}
    	else{
    		reception[num] = '\0';
    		printf("%s",reception);
    	}
    }

    pktif_mread_sendtime_sync(endpoint_obj, 0, &send); 

    printf("\n\nElapsed Time : %.3f ms\n", (float) ((recv - send)/1000000));

    pktif_close_sync(endpoint_obj, 1);

    freeaddrinfo(remote);
    
    free(endpoint_obj);

    return 0;
}

void findHTTPRequestString(char* url, char* request, char* website){
    char* prefix1 = "GET ";
    char* prefix2 = " HTTP/1.1\r\nHost: ";
    char* suffix = "\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nAccept: */*\r\n\r\n";
    request[0] = '\0';
    char* https = strstr(url, "https://");
    char* host;
    if(https)
        host = &(https[8]);
    else
        host = url;
    char* get = strchr(host, '/');
    strcat(request, prefix1);
    if(get == NULL)
        strcat(request, "/");
    else
        strcat(request, get);
    strcat(request, prefix2);
    if(get !=NULL)
        *get = '\0';
    strcat(request, host);
    strcat(request, suffix);
    strcpy(website, host);
    return;
}
