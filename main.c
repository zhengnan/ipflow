/******************************************************************************
*                                                                             *
*   File Name   : main.c                                                      *
*   Author      : LiuFeng                                                     *
*   Create Date : 2010-06-25                                                  *
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
#include "gnDb.h"
#include "gnUtls.h"
#include "gnFlow.h"
#include "gnPkt.h"
#include "gnproto.h"

#include "workque.h"

#include "cmdline.h"

///////////////////////////////////////////////////////////////////////////////
#ifndef MAX_RX_QUES
#define MAX_RX_QUES 16
#endif

#if 1
#define INLINE
#else
#define INLINE inline
#endif
///////////////////////////////////////////////////////////////////////////////
#pragma pack(1)

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

#pragma pack()

///////////////////////////////////////////////////////////////////////////////
#define PAD_LEN     20
#define CRC_LEN     4

#define NUM_CARDS   16
///////////////////////////////////////////////////////////////////////////////
int    flag_xmit=1;
int    flag_flow=0, flag_dpi=0, dpi_inited=0;

TAB_ID flow_tab[NUM_CARDS][MAX_RX_QUES]={{0}};
TAB_ID group_flowtab[MAX_RX_QUES]={0};
TAB_ID glob_flowtab=0;

TAB_ID flow_v6tab[NUM_CARDS][MAX_RX_QUES]={{0}};

UINT8  total_rxpkts[NUM_CARDS][MAX_RX_QUES], total_rxbytes[NUM_CARDS][MAX_RX_QUES];
UINT8  total_txpkts[NUM_CARDS][MAX_RX_QUES], total_txbytes[NUM_CARDS][MAX_RX_QUES];

UINT8  last_rxpkts[NUM_CARDS], last_rxbytes[NUM_CARDS];
UINT8  last_txpkts[NUM_CARDS], last_txbytes[NUM_CARDS];

int    rx_sockfd[NUM_CARDS], tx_sockfd[NUM_CARDS];
int    tx_ifindex[NUM_CARDS], rxtx_buddy[NUM_CARDS];
int    debug_flag=0, exit_flag=0;

UINT4  flowv4_memcnt=2000000;
UINT4  flowv6_memcnt=2000000;
UINT4  flow_tabsz = 1789103;
////////////////////////////////////////////////////////////////////////////////
#define DEBUG_FLOW  0x01
#define DEBUG_TCP   0x02
#define DEBUG_HTTP  0x04
#define DEBUG_UDP   0x80
#define DEBUG_DNS   0x100
#define DEBUG_APP   0x4000
#define DEBUG_STAT  0x8000

////////////////////////////////////////////////////////////////////////////////
#define HOST        "localhost"
#define DB_NAME     "Flow_Info"
#define USER_NAME   "admin"
#define PASSWD      "buptnic"
#define INSERT_SQL  "insert into flow (sip, dip, sport, dport, proto, appid, appname, bytes, pkts) values ('%s', '%s', '%d', '%d', '%d', '%d', '%s', '%u', '%u')"
////////////////////////////////////////////////////////////////////////////////
static inline UINT4 v6_hash(UINT1 *sip, UINT2 sport, UINT1 *dip, UINT2 dport, UINT4 hsize)
{
    return (((*((UINT4 *)(sip)+3))+(sport)+(dport))%(hsize));
}

static int db_insertV6(tIpV6Flow *flow)
{
	int handle;
	int retValue;
	char sql[500];

	retValue = db_init();

	if(retValue == DB_FAILURE)
	{
		printf("db_init failure!!\n");
		return -1;
	}

	handle = db_open(HOST, DB_NAME, USER_NAME, PASSWD, DB_MYSQL);

	if(handle == DB_FAILURE)
	{
		printf("open db failure!!\n");
		db_shutdown();
		return -1;
	}

	sprintf(sql, INSERT_SQL, inet6_htoa(flow->sip, NULL), inet6_htoa(flow->dip, NULL),
		gn_ntohs(flow->sport), gn_ntohs(flow->dport), flow->proto, flow->appid, 
		GetNamebyProtoId(flow->appid), flow->ext.up_bytes, flow->ext.up_pkts);

	retValue = db_excute(handle, sql);

	if(retValue == DB_FAILURE)
	{
		printf("excute sql failure!!\n");
		db_close(handle);
		db_shutdown();
		return -1;
	}

	db_close(handle);
	db_shutdown();

	return 1;

}

static void flow_timeout(void *owner, tTimer *tid)
{
    tIpV4Flow *flow = (tIpV4Flow *)owner;

    if (flow->state == FLOW_ALIVE)
    {
        flow->state = FLOW_DEAD;
        return;
    }

    if (debug_flag & DEBUG_FLOW)
    {
        printf("flow timeout, [id:%d, %s]: %s[%d] -> %s[%d]\n",
            flow->appid, GetNamebyProtoId(flow->appid),
            inet_htoa(gn_ntohl(flow->sip)), gn_ntohs(flow->sport),
            inet_htoa(gn_ntohl(flow->dip)), gn_ntohs(flow->dport));
    }

    kill_timer(tid);
    del_ipv4flow_safe(0, flow);
}

static void flow_v6timeout(void *owner, tTimer *tid)
{
	int isDb = -1;
    tIpV6Flow *flow = (tIpV6Flow *)owner;

    if (flow->state == FLOW_ALIVE)
    {
        flow->state = FLOW_DEAD;
        return;
    }

    isDb = db_insertV6(flow);

    if(isDb < 0)
    {
    	printf("db_insert failure!!\n");
    }
    if (debug_flag & DEBUG_FLOW)
    {
        printf("flow timeout, app[id:%d, %s]: %s[%d] -> %s[%d]\n",
            flow->appid, GetNamebyProtoId(flow->appid),
            inet6_htoa(flow->sip, NULL), gn_ntohs(flow->sport),
            inet6_htoa(flow->dip, NULL), gn_ntohs(flow->dport));
    }
    kill_timer(tid);
    del_ipv6flow_safe(0, flow);
}


static void init_dpi(int index, int num_ques)
{
    int qid, mem_cnt;

    switch (flag_flow)
    {
        case 1:
        {
            if (glob_flowtab)
                return;
            
            glob_flowtab = create_ipv4_flowtab(flow_tabsz, flowv4_memcnt, FLOW_EXTSIZE,
                                                CREAT_TCP|CREAT_UDP,
                                                30, (TimeFunc)flow_timeout, NULL);
        }
        break;

        case 2:
        {
            mem_cnt = flowv4_memcnt/MAX_RX_QUES;

            for (qid=0; qid<MAX_RX_QUES; qid++)
            {
                if (group_flowtab[qid])
                    continue;
                group_flowtab[qid] = create_ipv4_flowtab(flow_tabsz, mem_cnt, FLOW_EXTSIZE,
                                                    CREAT_TCP|CREAT_UDP,
                                                    30, (TimeFunc)flow_timeout, NULL);
            }
        }
        break;

        case 3:
        {
            mem_cnt = flowv4_memcnt/num_ques;

            for (qid=0; qid<num_ques; qid++)
            {
                if (flow_tab[index][qid])
                    continue;
                flow_tab[index][qid] = create_ipv4_flowtab(flow_tabsz, mem_cnt, FLOW_EXTSIZE,
                                                    CREAT_TCP|CREAT_UDP,
                                                    30, (TimeFunc)flow_timeout, NULL);
            }
        }
        break;

        default:
        break;
    }

    mem_cnt = flowv6_memcnt/num_ques;

    for (qid=0; qid<num_ques; qid++)
    {
        if (flow_v6tab[index][qid])
            continue;
        flow_v6tab[index][qid] = create_ipv6_flowtab(flow_tabsz, mem_cnt, FLOW_EXTSIZE,
                                            CREAT_TCP|CREAT_UDP,
                                            30, (TimeFunc)flow_v6timeout, v6_hash);

        if (flow_v6tab[index][qid])
        {
            int opt;

            opt = index;
            set_flowtab_opt(flow_v6tab[index][qid], FLOWTAB_IFINDEX, &opt);
            opt = qid;
            set_flowtab_opt(flow_v6tab[index][qid], FLOWTAB_PID, &opt);
        }
    }
}

#if 0
int logfd=-1;

static void log_pkt(tEthpkt *pkthdr, tIp *pIp)
{
    static UINT4 count=0;
    static int   rawip_mode=0;

    if (count++ >= 100)
    {
        LogPktClose(logfd);
        logfd = -1;
        return;
    }
    if (logfd <= 0)
    {
        //logfd = LogPktOpen("./pkt.cap", APPEND_MODE, PCAP_ETHER);
        //logfd = LogPktOpen("./pkt.cap", TRUC_MODE, PCAP_ETHER);

        logfd = LogPktOpen("./pkt.cap", TRUC_MODE, PCAP_RAWIP);
        if (logfd < 0)
            return;

        rawip_mode = 1;
    }

    if (rawip_mode)
        LogPkt(logfd, pIp, pkthdr->len - ((char *)pIp - (char *)pkthdr->pEth));
    else
        LogPkt(logfd, pkthdr->pEth, pkthdr->len);
}
#endif

static INLINE int proc_dpi_out(tEthpkt *pkthdr, tEther *pEth, tIp *pIp)
{
    tIpV4Flow *flow;
    int       index, pid, flag=PACKET_OUT;

    index   = rxtx_buddy[pkthdr->ifindex];

    switch (flag_flow)
    {
        case 1:
            flow = create_ipv4flow_safe_ext(glob_flowtab, pIp, &flag);
        break;
        case 2:
            pid  = pkthdr->rxqid;
            flow = create_ipv4flow_safe_ext(group_flowtab[pid], pIp, &flag);
        break;
        case 3:
            pid  = pkthdr->pid;
            flow = create_ipv4flow_safe_ext(flow_tab[index][pid], pIp, &flag);
        break;
        default:
            return 0;
        break;
    }
    if (!flow)
    {
        return 0;
    }
    if (flag == FLOW_NEW)
    {
        memset(flow->userdata, 0, FLOW_EXTSIZE);
        flow->ext.t_start = cur_sys_time.tv_sec;
        flow->ext.t_stop  = cur_sys_time.tv_sec;

        if ((debug_flag & DEBUG_FLOW) && flow)
        {
            printf("new ipv4flow (out): %s[%d] -> %s[%d]\n",
                inet_htoa(gn_ntohl(flow->sip)), gn_ntohs(flow->sport),
                inet_htoa(gn_ntohl(flow->dip)), gn_ntohs(flow->dport));
        }
    }
    else
    {
        if (flow->ext.t_stop != cur_sys_time.tv_sec)
            flow->ext.t_stop = cur_sys_time.tv_sec;

        if ((debug_flag & DEBUG_FLOW) && flow)
        {
            printf("find ipv4flow (out): %s[%d] -> %s[%d]\n",
                inet_htoa(gn_ntohl(flow->sip)), gn_ntohs(flow->sport),
                inet_htoa(gn_ntohl(flow->dip)), gn_ntohs(flow->dport));
        }
    }
    flow->ext.up_pkts++;
    flow->ext.up_bytes += pkthdr->len;

    if (flow->state == FLOW_DEAD)
        flow->state = FLOW_ALIVE;

    if (flag_dpi && !flow->appid)
    {
        flow->appid = AnalyzeProtoV4(PACKET_OUT, pIp, flow);
        if (debug_flag & DEBUG_APP)
        {
            if (flow->appid)
            {
                printf("[FindApp] (out) id:%d, %s, %s -> %s.\n",
                    flow->appid, GetNamebyProtoId(flow->appid),
                    inet_htoa(ntohl(pIp->src)), inet_htoa(ntohl(pIp->dest)));
            }
        }
    }

    return 1;
}

static INLINE int proc_dpi_in(tEthpkt *pkthdr, tEther *pEth, tIp *pIp)
{
    tIpV4Flow *flow;
    int       index, pid, flag=PACKET_IN;

    index   = rxtx_buddy[pkthdr->ifindex];
    pid     = pkthdr->pid;

    switch (flag_flow)
    {
        case 1:
            flow = create_ipv4flow_safe_ext(glob_flowtab, pIp, &flag);
        break;
        case 2:
            pid  = pkthdr->rxqid;
            flow = create_ipv4flow_safe_ext(group_flowtab[pid], pIp, &flag);
        break;
        case 3:
            pid  = pkthdr->pid;
            flow = create_ipv4flow_safe_ext(flow_tab[index][pid], pIp, &flag);
        break;
        default:
            return 0;
        break;
    }

    if (!flow)
    {
        return 0;
    }
    if (flag == FLOW_NEW)
    {
        memset(flow->userdata, 0, FLOW_EXTSIZE);
        flow->ext.t_start = cur_sys_time.tv_sec;
        flow->ext.t_stop  = cur_sys_time.tv_sec;

        if ((debug_flag & DEBUG_FLOW) && flow)
        {
            printf("new ipv4flow (in): %s[%d] -> %s[%d]\n",
                inet_htoa(gn_ntohl(flow->sip)), gn_ntohs(flow->sport),
                inet_htoa(gn_ntohl(flow->dip)), gn_ntohs(flow->dport));
        }
    }
    else
    {
        if (flow->ext.t_stop != cur_sys_time.tv_sec)
            flow->ext.t_stop = cur_sys_time.tv_sec;

        if ((debug_flag & DEBUG_FLOW) && flow)
        {
            printf("find ipv4flow (in): %s[%d] -> %s[%d]\n",
                inet_htoa(gn_ntohl(flow->sip)), gn_ntohs(flow->sport),
                inet_htoa(gn_ntohl(flow->dip)), gn_ntohs(flow->dport));
        }
    }
    flow->ext.down_pkts++;
    flow->ext.down_bytes += pkthdr->len;

    if (flow->state == FLOW_DEAD)
        flow->state = FLOW_ALIVE;

    if (flag_dpi && !flow->appid)
    {
        flow->appid = AnalyzeProtoV4(PACKET_IN, pIp, flow);
        if (debug_flag & DEBUG_APP)
        {
            if (flow->appid)
            {
                printf("[FindApp] (in) id:%d, %s, %s -> %s.\n",
                    flow->appid, GetNamebyProtoId(flow->appid),
                    inet_htoa(ntohl(pIp->src)), inet_htoa(ntohl(pIp->dest)));
            }
        }
    }
    return 1;
}

static INLINE int proc_v6dpi_out(tEthpkt *pkthdr, tEther *pEth, tIpv6 *pIpv6)
{
    tIpV6Flow *flow;
    int       index, pid, flag=PACKET_OUT;

    index   = rxtx_buddy[pkthdr->ifindex];
    pid     = pkthdr->pid;

    flow    = create_ipv6flow_safe_ext(flow_v6tab[index][pid], pIpv6, &flag);
    if (!flow)
    {
        return 0;
    }

    if (flag == FLOW_NEW)
    {
        memset(flow->userdata, 0, FLOW_EXTSIZE);
        flow->ext.t_start = cur_sys_time.tv_sec;
        flow->ext.t_stop  = cur_sys_time.tv_sec;

        if ((debug_flag & DEBUG_FLOW) && flow)
        {
            printf("new ipv6flow (out): %s[%d] -> %s[%d]\n",
                inet6_htoa(flow->sip, NULL), gn_ntohs(flow->sport),
                inet6_htoa(flow->dip, NULL), gn_ntohs(flow->dport));
        }
    }
    else
    {
        if (flow->ext.t_stop != cur_sys_time.tv_sec)
            flow->ext.t_stop = cur_sys_time.tv_sec;

        if ((debug_flag & DEBUG_FLOW) && flow)
        {
            printf("find ipv6flow (out): %s[%d] -> %s[%d]\n",
                inet6_htoa(flow->sip, NULL), gn_ntohs(flow->sport),
                inet6_htoa(flow->dip, NULL), gn_ntohs(flow->dport));
        }
    }

    flow->ext.up_pkts++;
    flow->ext.up_bytes += pkthdr->len;

    if (flow->state == FLOW_DEAD)
        flow->state = FLOW_ALIVE;

    if (flag_dpi && !flow->appid)
    {
        flow->appid = AnalyzeProtoV6(PACKET_OUT, pIpv6, flow);
        if (debug_flag & DEBUG_APP)
        {
            if (flow->appid)
            {
                printf("[FindApp] (out) id:%d, %s, %s -> %s.\n",
                    flow->appid, GetNamebyProtoId(flow->appid),
                    inet6_htoa(flow->sip, NULL), inet6_htoa(flow->dip, NULL));
            }
        }
    }

    return 1;
}

static INLINE int proc_v6dpi_in(tEthpkt *pkthdr, tEther *pEth, tIpv6 *pIpv6)
{
    tIpV6Flow *flow;
    int       index, pid, flag=PACKET_IN;

    index   = rxtx_buddy[pkthdr->ifindex];
    pid     = pkthdr->pid;

    flow    = create_ipv6flow_safe_ext(flow_v6tab[index][pid], pIpv6, &flag);
    if (!flow)
    {
        return 0;
    }
    if (flag == FLOW_NEW)
    {
        memset(flow->userdata, 0, FLOW_EXTSIZE);
        flow->ext.t_start = cur_sys_time.tv_sec;
        flow->ext.t_stop  = cur_sys_time.tv_sec;

        if ((debug_flag & DEBUG_FLOW) && flow)
        {
            printf("new ipv6flow (in): %s[%d] -> %s[%d]\n",
                inet6_htoa(flow->sip, NULL), gn_ntohs(flow->sport),
                inet6_htoa(flow->dip, NULL), gn_ntohs(flow->dport));
        }
    }
    else
    {
        if (flow->ext.t_stop != cur_sys_time.tv_sec)
            flow->ext.t_stop = cur_sys_time.tv_sec;

        if ((debug_flag & DEBUG_FLOW) && flow)
        {
            printf("find ipv6flow (in): %s[%d] -> %s[%d]\n",
                inet6_htoa(flow->sip, NULL), gn_ntohs(flow->sport),
                inet6_htoa(flow->dip, NULL), gn_ntohs(flow->dport));
        }
    }

    flow->ext.up_pkts++;
    flow->ext.up_bytes += pkthdr->len;

    if (flow->state == FLOW_DEAD)
        flow->state = FLOW_ALIVE;

    if (flag_dpi && !flow->appid)
    {
        flow->appid = AnalyzeProtoV6(PACKET_IN, pIpv6, flow);
        if (debug_flag & DEBUG_APP)
        {
            if (flow->appid)
            {
                printf("[FindApp] (in) id:%d, %s, %s -> %s.\n",
                    flow->appid, GetNamebyProtoId(flow->appid),
                    inet6_htoa(flow->sip, NULL), inet6_htoa(flow->dip, NULL));
            }
        }
    }

    return 1;
}

int procNapiPkt(tEthpkt *pkthdr, int count)
{
    void    *pIp, *pip2;
    tEthpkt *phdr;
    int     ii, ifindex, qid;
    UINT4   rxbytes=0;

    ifindex = pkthdr->ifindex;
    qid     = pkthdr->pid;
    phdr    = pkthdr;

#if 0 // only for test.
{
    char *dma_buf;

    for (ii=0; ii<100; ii++)
    {
        dma_buf = alloc_dmabuf(rx_sockfd);
        if (!dma_buf)
        {
            printf("alloc dmabuf failure!\n");
            break;
        }
        memcpy(dma_buf, phdr->pEth, phdr->len);
        dma_output(rx_sockfd, dma_buf, phdr->len, qid);
    }
    return count;
}
#endif

    if (flag_flow)
    {
        int pkt_type;

        if (pkthdr->inout == PACKET_OUT)
        {
            for (ii=0; ii<count; ii++)
            {
            #if 0
                if (phdr->pEth->proto == gn_ntohs(ETHERTYPE_IP))
                {
                    proc_dpi_out(phdr, phdr->pEth, (tIp *)phdr->pEth->data);
                }
            #else
                pIp      = NULL;
                pip2     = NULL;
                pkt_type = predo_layer3_pkt(phdr->pEth, &pIp, &pip2);

                switch (pkt_type)
                {
                    case PKT_IPV4_ONLY:
                    case PKT_IPV4_PPP:
                    case PKT_IPV4_PPP_VLAN:
                    case PKT_IPV4_PPP_2VLAN:
                    case PKT_IPV4_VLAN:
                    case PKT_IPV4_2VLAN:
                    case PKT_MPLS_VLAN:
                    case PKT_MPLS_ONLY:

                    case PKT_PPP_ONLY:
                    case PKT_PPP_VLAN:
                    case PKT_VLAN_ONLY:
                    case PKT_VLAN_PPP:
                    case PKT_VLAN_VLAN:
                    {
                        if (pIp)
                            proc_dpi_out(phdr, phdr->pEth, (tIp *)pIp);
                    }
                    break;

                    case PKT_IPV4_GRE:
                    {
                    #if 0
                        if (pip2)
                        {
                            printf("rx GRE packet, %s -> %s.\n",
                                inet_htoa(gn_ntohl(((tIp *)pip2)->src)),
                                inet_htoa(gn_ntohl(((tIp *)pip2)->dest)));
                        }
                    #endif
                    }
                    case PKT_IPV4_L2TP:
                    case PKT_IPV4_IPV4:
                    case PKT_IPV4_GTPC_V0:
                    case PKT_IPV4_GTPU_V0:
                    case PKT_IPV4_GTPC_V1:
                    case PKT_IPV4_GTPU_V1:
                        if (pip2)
                            proc_dpi_out(phdr, phdr->pEth, (tIp *)pip2);
                    break;

                    case PKT_IPV6_ONLY:
                    case PKT_IPV6_PPP:
                    case PKT_IPV6_PPP_VLAN:
                    case PKT_IPV6_PPP_2VLAN:
                    case PKT_IPV6_VLAN:
                    case PKT_IPV6_2VLAN:
                    {
                        if (pIp)
                            proc_v6dpi_out(phdr, phdr->pEth, (tIpv6 *)pIp);
                    }
                    break;
                    case PKT_IPV6_L2TP:
                    case PKT_IPV6_IPV4:
                        if (pip2)
                            proc_v6dpi_out(phdr, phdr->pEth, (tIpv6 *)pip2);
                    break;

                    default:
                    break;
                }
            #endif

                rxbytes += phdr->len;
                // if we set phdr->dma = NULL, this packet will be drop.

                phdr++;
            }
        }
        else
        {
            for (ii=0; ii<count; ii++)
            {
            #if 0
                if (phdr->pEth->proto == gn_ntohs(ETHERTYPE_IP))
                {
                    proc_dpi_in(phdr, phdr->pEth, (tIp *)phdr->pEth->data);
                }
            #else
                pIp      = NULL;
                pip2     = NULL;
                pkt_type = predo_layer3_pkt(phdr->pEth, &pIp, &pip2);

                switch (pkt_type)
                {
                    case PKT_IPV4_ONLY:
                    case PKT_IPV4_PPP:
                    case PKT_IPV4_PPP_VLAN:
                    case PKT_IPV4_PPP_2VLAN:
                    case PKT_IPV4_VLAN:
                    case PKT_IPV4_2VLAN:
                    case PKT_IPV4_MPLS_VLAN:
                    case PKT_IPV4_MPLS:

                    case PKT_PPP_VLAN:
                    case PKT_VLAN_ONLY:
                    case PKT_VLAN_PPP:
                    case PKT_VLAN_VLAN:
                    {
                        if (pIp)
                            proc_dpi_in(phdr, phdr->pEth, pIp);
                    }
                    break;
                    case PKT_IPV4_GRE:
                    case PKT_IPV4_L2TP:
                    case PKT_IPV4_IPV4:
                    case PKT_IPV4_GTPC_V0:
                    case PKT_IPV4_GTPU_V0:
                    case PKT_IPV4_GTPC_V1:
                    case PKT_IPV4_GTPU_V1:
                        if (pip2)
                            proc_dpi_in(phdr, phdr->pEth, (tIp *)pip2);
                    break;

                    case PKT_IPV6_ONLY:
                    case PKT_IPV6_PPP:
                    case PKT_IPV6_PPP_VLAN:
                    case PKT_IPV6_PPP_2VLAN:
                    case PKT_IPV6_VLAN:
                    case PKT_IPV6_2VLAN:
                    {
                        if (pIp)
                            proc_v6dpi_in(phdr, phdr->pEth, (tIpv6 *)pIp);
                    }
                    break;
                    case PKT_IPV6_L2TP:
                    case PKT_IPV6_IPV4:
                        if (pip2)
                            proc_v6dpi_in(phdr, phdr->pEth, (tIpv6 *)pip2);
                    break;

                    default:
                    break;
                }
            #endif

                rxbytes += phdr->len;
                // if we set phdr->dma = NULL, this packet will be drop.

                phdr++;
            }
        }

        if (flag_xmit && (tx_ifindex[ifindex] < NUM_CARDS))
        {
            phdr = pkthdr;
        #if 0
            for (ii=0; ii<count; ii++)
            {
                xmit_packet(tx_ifindex[ifindex], phdr->pid, phdr);
                phdr++;
            }
        #else
            napi_xmit_packet(tx_ifindex[ifindex], phdr->rxqid, phdr, count);
        #endif
        }
    }
    else
    {
        for (ii=0; ii<count; ii++)
        {
            rxbytes += phdr->len;

            //if (phdr->flag)
            //    printf("first here!!!!\n");
            // if we set phdr->dma = NULL, this packet will be drop.
            phdr++;
        }
        if (flag_xmit && (tx_ifindex[ifindex] < NUM_CARDS))
        {
            phdr = pkthdr;

        #if 0
            for (ii=0; ii<count; ii++)
            {
                xmit_packet(tx_ifindex[ifindex], phdr->rxqid, phdr);
                phdr++;
            }
        #else
            napi_xmit_packet(tx_ifindex[ifindex], phdr->rxqid, phdr, count);
        #endif
        }
    }

    total_rxpkts[ifindex][qid]  += count;
    total_rxbytes[ifindex][qid] += rxbytes;

    if (flag_xmit && (tx_ifindex[ifindex] < NUM_CARDS))
    {
        total_txpkts[tx_ifindex[ifindex]][qid]  += count;
        total_txbytes[tx_ifindex[ifindex]][qid] += rxbytes;
    }

    return count;
}

////////////////////////////////////////////////////////////////////////////////
void show_help()
{
    printf("\nhelp of libtest.\n");
    printf("-rethx        ---- receive packet from ethx.\n");
    printf("-rethx -xethy ---- packet from ethx to ethy, and ethy to ethx.\n");
    printf("-m            ---- -m0 receive mode, other peekmode.\n");
    printf("-dpi          ---- flow & dpi.\n");
    printf("-debug        ---- enable debug mode.\n");
    printf("-n x          ---- number of threads each card(only for 10G cards).\n");
    printf("-noxmit       ---- disable xmit.\n");
    printf("-txcycle n    ---- set tx notify cycle.\n");
    printf("-rxcycle n    ---- set rx notify cycle.\n");
    printf("--help        ---- show help.\n");
}

static void cleanup(int signo)
{
    if (exit_flag)
        return;

	exit_flag = 1;
}

int main(int argc, char** argv)
{
    int   i, opt=0;
    //int rx_mode=RAW_MODE, tx_mode=RAW_MODE;
    int   rx_mode=DMA_MODE, tx_mode=DMA_MODE;
    int   recv_mode;
    char  rxif[NUM_CARDS][128], txif[NUM_CARDS][128];
    char  ifname[16], *pif, *bindstr;
    char  *ptr;
    int   ifindex, rx_index=0, tx_index=0;
    int   rx_port[NUM_CARDS], tx_port[NUM_CARDS];
    int   qid, numproc=1;

#if 0 // set sched pri
    pthread_attr_t attr;
    struct sched_param param;
    int    policy  = SCHED_RR;//SCHED_FIFO;
    int    newprio = sched_get_priority_max(policy)-1;
    pthread_attr_init(&attr);
    pthread_attr_setschedpolicy(&attr, policy);
    pthread_attr_getschedparam(&attr, &param);
    param.sched_priority=newprio;
    pthread_attr_setschedparam(&attr, &param);
#endif

    lib_init(); // initialize lib.
    //printf("\n%s", lib_version());

    memset(rx_port, -1, sizeof(rx_port));
    memset(tx_port, -1, sizeof(tx_port));

    memset(rx_sockfd, -1, sizeof(rx_sockfd));
    memset(tx_sockfd, -1, sizeof(tx_sockfd));
    memset(rxtx_buddy, -1, sizeof(rxtx_buddy));

    for (i=0; i<NUM_CARDS; i++)
        tx_ifindex[i] = NUM_CARDS;

    init_syslog("testprog"); // initialize log service.
    set_sysdebug(1);

    memset(rxif, 0, sizeof(rxif));
    memset(txif, 0, sizeof(txif));

    recv_mode = PEEK_MODE;

    for (i=1; i<argc; i++)
    {
        if (!strncmp(argv[i], "-raw", 4))
        {
            rx_mode = RAW_MODE;
            tx_mode = RAW_MODE;
        }
        else if (!strncmp(argv[i], "-m", 2))
        {
            pif = argv[i];
            pif += 2;
            sscanf(pif, "%d", &recv_mode);
        }
        else if (!strncmp(argv[i], "-flow", 5))
        {
            ptr = argv[i]+5;
            if (*ptr == ':')
            {
                ptr++;
                sscanf(ptr, "%d", &flag_flow);
                if (flag_flow > 3)
                    flag_flow = 3;
            }
            else
                flag_flow = 3;
        }
        else if (!strcmp(argv[i], "-dpi"))
        {
            flag_dpi  = 1;
            flag_flow = 3;
        }
        else if (!strcmp(argv[i], "-n"))
        {
            numproc = atoi(argv[i+1]);
            i++;
        }
        else if (!strncmp(argv[i], "-debug:", 7))
        {
            sscanf(argv[i], "-debug:%x", &debug_flag);
        }
        else if (!strcmp(argv[i], "-noxmit"))
        {
            flag_xmit = 0;
        }
        else if (!strcmp(argv[i], "-txcycle"))
        {
            opt = atoi(argv[i+1]);
            i++;
            set_sockopt(0, SET_TX_NOTIFY, &opt);
        }
        else if (!strcmp(argv[i], "-rxcycle"))
        {
            opt = atoi(argv[i+1]);
            i++;
            set_sockopt(0, SET_RX_NOTIFY, &opt);
        }
        else if (!strncmp(argv[i], "-r", 2))
        {
            sprintf(rxif[rx_index++], "%s", argv[i]+2);
        }
        else if (!strncmp(argv[i], "-x", 2))
        {
            sprintf(txif[tx_index++], "%s", argv[i]+2);
        }
        else
        {
            show_help();
            exit(0);
        }
    }

    if (recv_mode == PEEK_MODE)
    {
        // disable xmit, if mode is PEEK_MODE.
        flag_xmit = 0;
    }

    printf("start test prog now...\n");

    for (i=0; i<NUM_CARDS; i++)
    {
        if (rxif[i][0])
        {
            pif = rxif[i];
            sscanf(pif, "eth%d", &ifindex);
            sprintf(ifname, "eth%d", ifindex);

            rx_port[i] = ifindex;
            if (ifindex < 10)
                pif += 4;
            else
                pif += 5;

            if (*pif == ':')
            {
                bindstr = pif+1;
            }
            else
                bindstr = NULL;

            //printf("---- open_sock %s ----\n", ifname);
            rx_sockfd[ifindex] = open_sock(ifname, rx_mode, tx_mode, recv_mode, numproc);
            if (rx_sockfd[ifindex] < 0)
            {
                printf("open_sock %s failure!\n", ifname);
            }
            else
                printf("open_sock %s success!\n", ifname);

            // set packet direction
            opt = PACKET_OUT;
            set_sockopt(rx_sockfd[ifindex], SET_IF_INOUT, &opt);

            if (!bindstr)
            {
                bindstr = "1:1:1:1:1:1:1:1";
            }
            set_sockopt(rx_sockfd[ifindex], SET_BINDING, (int *)bindstr);
        }
    }

    for (i=0; i<NUM_CARDS; i++)
    {
        if (txif[i][0])
        {
            pif = txif[i];
            sscanf(pif, "eth%d", &ifindex);
            sprintf(ifname, "eth%d", ifindex);

            tx_port[i] = ifindex;
            if (ifindex < 10)
                pif += 4;
            else
                pif += 5;

            if (*pif == ':')
            {
                bindstr = pif+1;
            }
            else
                bindstr = NULL;

            //printf("---- open_sock %s ----\n", ifname);
            tx_sockfd[ifindex] = open_sock(ifname, rx_mode, tx_mode, recv_mode, numproc);
            if (tx_sockfd[ifindex] < 0)
            {
                printf("open_sock %s failure!\n", ifname);
            }
            else
                printf("open_sock %s success!\n", ifname);


            // set packet direction
            opt = PACKET_IN;
            set_sockopt(tx_sockfd[ifindex], SET_IF_INOUT, &opt);

            if (!bindstr)
            {
                bindstr = "2:2:2:2:2:2:2:2";
            }

            set_sockopt(tx_sockfd[ifindex], SET_BINDING, (int *)bindstr);
        }
    }

    memset(flow_tab, 0, sizeof(flow_tab));
    memset(group_flowtab, 0, sizeof(group_flowtab));

    if (flag_flow)
    {
        printf("init flow tables......\n");

        for (i=0; i<NUM_CARDS; i++)
        {
            if (rx_port[i] >= 0)
            {
                rxtx_buddy[rx_port[i]] = i;
            }
            if (tx_port[i] >= 0)
            {
                rxtx_buddy[tx_port[i]] = i;
            }

            if (rxtx_buddy[i] >= 0)
                init_dpi(rxtx_buddy[i], numproc);
        }
    }
    if (flag_dpi)
    {
        printf("init dpi parser......\n");
        InitProtoAnalyzer();
    }

    for (i=0; i<NUM_CARDS; i++)
    {
        if (rx_sockfd[i] >= 0)
        {
            set_napi_proc(rx_sockfd[i], (RX_NAPI)procNapiPkt);
            start_proc(rx_sockfd[i]);
        }

        if (tx_sockfd[i] >= 0)
        {
            set_napi_proc(tx_sockfd[i], (RX_NAPI)procNapiPkt);
            start_proc(tx_sockfd[i]);
        }
    }

    for (i=0; i<NUM_CARDS; i++)
    {
        if ((rx_port[i] >= 0) && (tx_port[i] >= 0))
        {
            tx_ifindex[rx_port[i]] = tx_sockfd[tx_port[i]];
            tx_ifindex[tx_port[i]] = rx_sockfd[rx_port[i]];
        }
    }

	(void)signal(SIGPIPE, cleanup);
	(void)signal(SIGTERM, cleanup);
	(void)signal(SIGINT, cleanup);

    write_log(LOG_SYS_INFO, "test prog started.\n");
    usleep(1000);

    set_sysdebug(0);

    memset((void *)total_rxpkts, 0, sizeof(total_rxpkts));
    memset((void *)total_rxbytes, 0, sizeof(total_rxbytes));
    memset((void *)total_txpkts, 0, sizeof(total_txpkts));
    memset((void *)total_txbytes, 0, sizeof(total_txbytes));

    memset((void *)last_rxpkts, 0, sizeof(last_rxpkts));
    memset((void *)last_rxbytes, 0, sizeof(last_rxbytes));
    memset((void *)last_txpkts, 0, sizeof(last_txpkts));
    memset((void *)last_txbytes, 0, sizeof(last_txbytes));

    while (!exit_flag)
    {
        static int last_flag[NUM_CARDS]={0}, flag3=1;
        int    ifindex, flag = 0, flag2=0;
        UINT8  rx_pkts[NUM_CARDS], rx_bytes[NUM_CARDS];
        UINT8  tx_pkts[NUM_CARDS], tx_bytes[NUM_CARDS];

        sleep(1);
        fflush(stdout);

     #if 0
        {
            time_t start=0, stop=0;
            struct tm when;

            get_licstat(&start, &stop);

            when = *localtime(&start);
            printf("lic start: %4d-%02d-%02d 00:00:00\n", 
                when.tm_year+1900, when.tm_mon+1, when.tm_mday);

            when = *localtime(&stop);
            printf("lic stop: %4d-%02d-%02d 00:00:00\n", 
                when.tm_year+1900, when.tm_mon+1, when.tm_mday);
        }
     #endif

        if (flag_flow)
        {
            int tcpflows, udpflows, otherflows, ii, index;
            int i1, i2, i3;

            tcpflows   = 0;
            udpflows   = 0;
            otherflows = 0;

            for (index=0; index<NUM_CARDS; index++)
            {
                for (ii=0; ii<numproc; ii++)
                {
                    if (flow_tab[index][ii])
                    {
                        i1 = 0;
                        i2 = 0;
                        i3 = 0;
                        get_flowtab_stat(flow_tab[index][ii], &i1, &i2, &i3);
                        tcpflows   += i1;
                        udpflows   += i2;
                        otherflows += i3;
                    }
                }
            }

            for (ii=0; ii<MAX_RX_QUES; ii++)
            {
                if (group_flowtab[ii])
                {
                    i1 = 0;
                    i2 = 0;
                    i3 = 0;
                    get_flowtab_stat(group_flowtab[ii], &i1, &i2, &i3);
                    tcpflows   += i1;
                    udpflows   += i2;
                    otherflows += i3;
                }
            }

            if (glob_flowtab)
            {
                i1 = 0;
                i2 = 0;
                i3 = 0;
                get_flowtab_stat(glob_flowtab, &i1, &i2, &i3);
                tcpflows   += i1;
                udpflows   += i2;
                otherflows += i3;
            }

            //if (flag3 && (debug_flag & (DEBUG_FLOW|DEBUG_DNS)))
            if (flag3)
            {
                printf("tcpflows:%d, udpflows:%d, otherflows:%d.\n",
                    tcpflows, udpflows, otherflows);
            }
            if (tcpflows || udpflows || otherflows)
            {
                flag3 = 1;
            }
            else
                flag3 = 0;
        }

        for (ifindex=0; ifindex<NUM_CARDS; ifindex++)
        {
        #if 1
            if (debug_flag & DEBUG_STAT)
            {
                tIfStat rxstat;

                memset((char *)&rxstat, 0, sizeof(tIfStat));
                if (rx_sockfd[ifindex] >= 0)
                {
                    get_sockopt(rx_sockfd[ifindex], GET_IF_RXTX_STAT, (int *)&rxstat);
                #ifdef X86_64
                    printf("[sysstat] eth%d rx:%lu Bytes, %lu pkts, %lu bps, %u pps.\n",
                        rx_sockfd[ifindex], rxstat.rx_bytes, rxstat.rx_pkts,
                        rxstat.rx_bps*8+rxstat.rx_pps*PAD_LEN*8, rxstat.rx_pps);
                    printf("[sysstat] eth%d tx:%lu Bytes, %lu pkts, %lu bps, %u pps.\n",
                        rx_sockfd[ifindex], rxstat.tx_bytes, rxstat.tx_pkts,
                        rxstat.tx_bps*8+rxstat.tx_pps*PAD_LEN*8, rxstat.tx_pps);
                #else
                    printf("[sysstat] eth%d rx:%lld Bytes, %lld pkts, %lld bps, %u pps.\n",
                        rx_sockfd[ifindex], rxstat.rx_bytes, rxstat.rx_pkts,
                        rxstat.rx_bps*8+rxstat.rx_pps*PAD_LEN*8, rxstat.rx_pps);
                    printf("[sysstat] eth%d tx:%lld Bytes, %lld pkts, %lld bps, %u pps.\n",
                        rx_sockfd[ifindex], rxstat.tx_bytes, rxstat.tx_pkts,
                        rxstat.tx_bps*8+rxstat.tx_pps*PAD_LEN*8, rxstat.tx_pps);
                #endif
                }
                if ((tx_sockfd[ifindex] >= 0) && (rx_sockfd[ifindex] != tx_sockfd[ifindex]))
                {
                    get_sockopt(tx_sockfd[ifindex], GET_IF_RXTX_STAT, (int *)&rxstat);
                #ifdef X86_64
                    printf("[sysstat] eth%d rx:%lu Bytes, %lu pkts, %lu bps, %u pps.\n",
                        tx_sockfd[ifindex], rxstat.rx_bytes, rxstat.rx_pkts,
                        rxstat.rx_bps*8+rxstat.rx_pps*PAD_LEN*8, rxstat.rx_pps);
                    printf("[sysstat] eth%d tx:%lu Bytes, %lu pkts, %lu bps, %u pps.\n",
                        tx_sockfd[ifindex], rxstat.tx_bytes, rxstat.tx_pkts,
                        rxstat.tx_bps*8+rxstat.tx_pps*PAD_LEN*8, rxstat.tx_pps);
                #else
                    printf("[sysstat] eth%d rx:%lld Bytes, %lld pkts, %lld bps, %u pps.\n",
                        tx_sockfd[ifindex], rxstat.rx_bytes, rxstat.rx_pkts,
                        rxstat.rx_bps*8+rxstat.rx_pps*PAD_LEN*8, rxstat.rx_pps);
                    printf("[sysstat] eth%d tx:%lld Bytes, %lld pkts, %lld bps, %u pps.\n",
                        tx_sockfd[ifindex], rxstat.tx_bytes, rxstat.tx_pkts,
                        rxstat.tx_bps*8+rxstat.tx_pps*PAD_LEN*8, rxstat.tx_pps);
                #endif
                }
            }
        #endif

            rx_pkts[ifindex]  = 0;
            rx_bytes[ifindex] = 0;
            tx_pkts[ifindex]  = 0;
            tx_bytes[ifindex] = 0;

            for (qid=0; qid<MAX_RX_QUES; qid++)
            {
                rx_pkts[ifindex]  += total_rxpkts[ifindex][qid];
                rx_bytes[ifindex] += total_rxbytes[ifindex][qid];

                tx_pkts[ifindex]  += total_txpkts[ifindex][qid];
                tx_bytes[ifindex] += total_txbytes[ifindex][qid];
            }

            if ((rx_pkts[ifindex]!=last_rxpkts[ifindex])
                || (tx_pkts[ifindex]!=last_txpkts[ifindex]))
            {
                flag                = 1;
                last_flag[ifindex]  = 1;
            }
            else
            {
                if (last_flag[ifindex])
                    flag = 1;
                else
                    flag = 0;
                last_flag[ifindex] = 0;
            }
            if (flag)
            {
                UINT8 rx_bps, tx_bps, rx_pps, tx_pps;

                rx_pps = (rx_pkts[ifindex]-last_rxpkts[ifindex]);
                tx_pps = (tx_pkts[ifindex]-last_txpkts[ifindex]);

                rx_bps = (rx_pkts[ifindex]-last_rxpkts[ifindex]) + rx_pps*(CRC_LEN+PAD_LEN);

                tx_bps = (tx_pkts[ifindex]-last_txpkts[ifindex]) + tx_pps*(CRC_LEN+PAD_LEN);

            #ifdef X86_64
                printf("eth%d, [rx] %lu pkts, %lu Bytes, pps:%lu, bps:%lu [tx] %lu pkts, pps:%lu, bps:%lu.\n",
                    ifindex, rx_pkts[ifindex], rx_bytes[ifindex],
                    rx_pps, rx_bps, tx_pkts[ifindex], tx_pps, tx_bps
                    );
            #else
                printf("eth%d, [rx] %lld pkts, %lld Bytes, pps:%lld, bps:%lld [tx] %lld pkts, pps:%lld, bps:%lld.\n",
                    ifindex, rx_pkts[ifindex], rx_bytes[ifindex],
                    rx_pps, rx_bps, tx_pkts[ifindex], tx_pps, tx_bps
                    );
            #endif
                flag2 = 1;
            }
            last_rxpkts[ifindex]  = rx_pkts[ifindex];
            last_rxbytes[ifindex] = rx_bytes[ifindex];

            last_txpkts[ifindex]  = tx_pkts[ifindex];
            last_txbytes[ifindex] = tx_bytes[ifindex];
        }
        if (flag2)
            printf("---------------------------------\n");
    }

    set_sysdebug(1);
    write_log(LOG_SYS_INFO, "test prog stopping......\n");

    // finish.
    for (i=0; i<NUM_CARDS; i++)
    {
        if (rx_sockfd[i] >= 0)
        {
            close_sock(rx_sockfd[i]);
        }

        if (tx_sockfd[i] >= 0)
        {
            close_sock(tx_sockfd[i]);
        }
    }

    if (flag_dpi)
    {
        ShutProtoAnalyzer();

        for (i=0; i<NUM_CARDS; i++)
        {
            for (qid=0; qid<numproc; qid++)
            {
                if (flow_tab[i][qid])
                    delete_ipv4_flowtab(flow_tab[i][qid]);
            }

            for (qid=0; qid<MAX_RX_QUES; qid++)
            {
                if (group_flowtab[qid])
                    delete_ipv4_flowtab(group_flowtab[qid]);
            }
        }
        if (glob_flowtab)
            delete_ipv4_flowtab(glob_flowtab);
    }

    shut_syslog();

    return 0;
}

