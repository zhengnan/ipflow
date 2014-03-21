/******************************************************************************
*                                                                             *
*   File Name   : main_001.c                                                  *
*   Author      : zhengnan                                                    *
*   Create Date : 2014-03-17                                                  *
*   Version     : 1.0                                                         *
*   Function    :                                                             *
*                                                                             *
******************************************************************************/

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
#include "gnproto.h"

#include "workque.h"

#include "cmdline.h"

//////////////////////////////////////////////////////////////////////////////
#ifndef MAX_RX_QUES
#define MAX_RX_QUES 8
#endif
//////////////////////////////////////////////////////////////////////////////

int dpi_flag = 0;
int xmit_flag = 1;

TAB_ID flow_v6tab[MAX_RX_QUES]={0};
tQueId v6q_tab[MAX_RX_QUES]={0};

int rx_port = -1;
int tx_port = -1;

UINT4  flow_tabsz = 178911;

static void init_dpi(int num_ques)
{
	int qid;

	for(qid=0; qid<num_ques; qid++){
		flow_v6tab[qid] = create_ipv6_flowtab(flow_tabsz, 1000, 0, CREAT_TCP | CREAT_UDP | CREAT_OTHER, 
			30, (TimeFunc)flow_v6timeout, NULL);

		v6q_tab[qid] = que_create(2000);
		if(flow_v6tab[qid]){
			int opt;

			opt = rx_port;
			set_flowtab_opt(flow_v6tab[qid], SET_FLOWTAB_IFINDEX, &opt);

			opt = qid;
			set_flowtab_opt(flow_v6tab[qid], SET_FLOWTAB_PID, &opt);
		}
	}
}

void show_help()
{
	printf("\nHelp of software.\n");
	printf("-rethx        ----recive packets from ethx.\n");
	printf("-m            ----m0 receive mode, other peekmode.\n");
	printf("-dpi          ----enable dpi mode.\n");
	printf("-t            ----number of thread.\n");
	printf("-help         ----help infomation.\n");
}

int main(int argc, char** argv)
{
	int i, opt = 0;
	int rx_mode = DMA_MODE;
	int tx_mode = DMA_MODE;
	int rx_sockfd = -1;
	int tx_sockfd = -1;
	int numproc = 1;
	int recv_mode;
	char* pif;
	char* bindstr = NULL;
	char rxif[128];
	char ifname[16];

	lib_init();

	for(i=1; i<argc; i++){
		if(!strncmp(argv[i], "-dpi", 4)){
			dpi_flag = 1;
		}
		else if(!strncmp(argv[i], "-r", 2)){
			sprintf(rxif, "%s", argv[i]+2);
		}
		else if(!strncmp(argv[i], "-m", 2)){
			pif = argv[i];
			pif += 2;
			sscanf(pif, "%d", &recv_mode);
		}
		else if(!strncmp(argv[i], "-t", 2)){
			pif = argv[i];
			pif += 2;
			scanf(pif, "%d", &numproc);

		}
		else
		{
			show_help();
			exit(0);
		}
	}

	if(recv_mode == PEEK_MODE){
		xmit_flag = 0;
	}

	if(rxif[0]){
		pif = rxif;
		sscanf(pif, "eth%d", &rx_port);
		sprintf(ifname, "eth%d", rx_port);

		rx_sockfd = open_sock(ifname, rx_mode, tx_mode, recv_mode, numproc);
		if(rx_sockfd < 0){
			printf("open_sock %s failure!\n", ifname);
			return -1;
		}

		opt = PACKET_OUT;
		set_sockopt(rx_sockfd, SET_IF_INOUT, &opt);

		if(numproc == 2){
			bindstr = "1:2";
		}
		else if(numproc == 4){
			bindstr = "1:2:3:4";
		}
		set_sockopt(rx_sockfd, SET_BINDING, (int *)bindstr);
		
	}

	memset(flow_v6tab, 0, sizeof(flow_v6tab));

	if(dpi_flag){
		init_dpi(numproc);
		InitProtoAnalyzer();
	}

	if(rx_sockfd>=0){
		#if 0
			set_frame_proc(rx_sockfd, (RX_PROC)ProcIpPkt);
		#else
			set_napi_proc(rx_sockfd, (RX_NAPI)ProcNapiPkt);
		#endif
	}

	return 0;
}