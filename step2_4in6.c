#include "gnInclude.h"
#include "libcom.h"

#include "gnMutex.h"
#include "gnMem.h"
#include "gnLog.h"
#include "gnTimer.h"
#include "gnNet.h"
#include "gnUtls.h"
#include "gnFlow.h"
#include "gnPkt.h"
#include "gnDb.h"
#include "gnproto.h"

#include "workque.h"

#include "cmdline.h"

int rx_port = -1;
int sockfd  = -1;

static int ProcIpPkt(tEthpkt *pkthdr, tIpv6 *pIpv6) {
	UINT1 next_header = pIpv6->next_head;
	tIp *pIpv4 = NULL;
	if( next_header == 4 ){
		printf("A 4in6 packet in...\n");
	}
	else{
		return -1;
	}
	
	pIpv4 = (tIp *)pIpv6->data;
	
	printf("ipv4 information:%s -> %s, proto[%d]\n",inet_htoa(gn_ntohl(pIpv4->src)), inet_htoa(gn_ntohl(pIpv4->dest)), pIpv4->proto);

	return 0;
}



int main(int argc, char** argv){
	int rx_mode = DMA_MODE,tx_mode = DMA_MODE;
	int recv_mode = RECEIVE_MODE;
	char ifname[10] = {0}, *bindstr;
	char rxif[128], *pif;
	int numproc = 4, i = 0;
	
	lib_init();
	
	for(i=1; i<argc; i++){
		if(!strncmp(argv[i], "-r", 2)){
			sprintf(rxif, "%s", argv[i]+2);
		}
	}
	pif = rxif;
	sscanf(pif, "eth%d", &rx_port);
	sprintf(ifname, "eth%d", rx_port);
			
	sockfd = open_sock(ifname, rx_mode, tx_mode, recv_mode, numproc);
	if(sockfd < 0)
	{
		printf("open_sock %s failure!\n",ifname);
	}
	else
	{
		printf("open_sock %s success!\n",ifname);
	}
	
	bindstr = "1:2:3:4";
	set_ipv6_proc(sockfd,(RX_PROC)ProcIpPkt);
	set_sockopt(sockfd,SET_BINDING,bindstr);
	
	start_proc(sockfd);
	
	printf("start now...\n");
		
	while(1)
	{
		
	}
	
	close_sock(sockfd);
	
	return 0;
}