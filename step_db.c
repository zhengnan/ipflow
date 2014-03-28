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

#define PAD_LEN 20
//#define FILENAME "/var/www/html/ipflow/flowNow"
#define HOST        "localhost"
#define DB_NAME     "Flow_Info"
#define USER_NAME   "admin" 
#define PASSWD      "buptnic"

typedef struct _st_IfStat
{
    UINT8       rx_bytes;
    UINT8       rx_pkts;
    UINT8       tx_bytes;
    UINT8       tx_pkts;

    UINT8       rx_bps;
    UINT8       tx_bps;
    UINT4       rx_pps;
    UINT4       tx_pps;
} tIfStat;

int rx_port = -1;
int sockfd  = -1;
int debug_flag = 0;

/*
int write_in_file(UINT8 rx_bps, UINT4 rx_pps){
	FILE* fileName = NULL;
	fileName = fopen(FILENAME, "w");
	if(!fileName){
		printf("Open file failed!\n");
		return -1;
	}
	fprintf(fileName, "eth%d %lu bps, %u pps.", sockfd,rx_bps*8+rx_pps*PAD_LEN*8, rx_pps);
	if(fprintf < 0){
		printf("fprintf wrong!\n");
		return -1;
	}
	fclose(fileName);
	return 0;
	
}
*/
int db_update(UINT8 bps, UINT4 pps){
	int handle;
	int retValue;
	char sql[100];

	retValue = db_init();
	if(retValue == DB_FAILURE){
		if(debug_flag){
			printf("db_init failure!\n");
		}
		return -1;
	}

	handle = db_open(HOST, DB_NAME, USER_NAME, PASSWD, DB_MYSQL);
	if(handle == DB_FAILURE){
		if(debug_flag){
			printf("open database failure!\n");
		}
		db_shutdown();
		return -1;
	}

	sprintf(sql, "insert into flow_now (bps, pps) values (%lu, %u)", bps,pps);

	retValue = db_excute(handle, sql);
	if(retValue == DB_FAILURE){
		if(debug_flag){
			printf("excute sql failure!\n");
		}
		db_close(handle);
		db_shutdown();
		return -1;
	}

	db_close(handle);
	db_shutdown();

	return 1;

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
	set_sockopt(sockfd,SET_BINDING,bindstr);
	
	start_proc(sockfd);
	
	printf("start now...\n");
		
	while(1)
	{
		tIfStat rxstat;
		get_sockopt(sockfd, GET_IF_RXTX_STAT, (int *)&rxstat);
		system("clear");
		//write_in_file(rxstat.rx_bps, rxstat.rx_pps);
		db_update(rxstat.rx_bps, rxstat.rx_pps);
        printf("eth%d %lu bps, %u pps.\n", sockfd,
            rxstat.rx_bps*8+rxstat.rx_pps*PAD_LEN*8, rxstat.rx_pps);
		sleep(10);
		system("clear");
	}
	
	close_sock(sockfd);
	
	return 0;
}