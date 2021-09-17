#include "../pktlab-libpktlab/include/pktif.h"
#include <string.h>

int main(){

    char* word_message = "I just fartedddd.";
    struct sockaddr_in loc;
    loc.sin_family = AF_INET;
    loc.sin_port = htons(6969);
    loc.sin_addr.s_addr = INADDR_ANY;
    memset(loc.sin_zero, 0, sizeof(unsigned char)*8);
    int socket = pktif_ep_accept((struct sockaddr*) &loc);
    struct pktif* loc_obj = pktif_init(socket,(struct sockaddr*) &loc);
    if (loc_obj == NULL){
        printf("Initialization failed.\n");
        return 0;
    }

    loc.sin_family = AF_INET;
    loc.sin_port = htons(4500);
    inet_pton(AF_INET, "127.0.0.1", &(loc.sin_addr));

    int connect_status = pktif_connect_sync(loc_obj, 1, 0x0c, 0,(struct sockaddr*) &loc, 0x1000, NULL);
    printf("Connection status : %d\n", connect_status);

    int send_status = pktif_send_sync(loc_obj,1, word_message, strlen(word_message),0, 0, 0x0c, NULL);
    printf("Sending status : %d\n", send_status);

    int close_status = pktif_close_sync(loc_obj,1);
    printf("Closing status : %d\n", close_status);

}