/********************************************
 *
 * @brief pcap文件读写类,不依赖PCAP头文件及库
 * @author kettas
 * @date 2016/3/25
 *
 *******************************************/

#ifndef _PCAP_OPER_H
#define _PCAP_OPER_H


#include <assert.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>


#define  PACKET_SIZE                    (140)
#define  COOKED_CAPTURE_SIZE            (16)
#define  IP_HEADER_SIZE             	(20)
#define  UDP_HEADER_SIZE          		(8)
#define  RTP_HEADER_SIZE           		(12)
#define  RTP_DATA_SIZE                  (84)
#define  MAX_FILENAME_LEN               (64)


// pcap文件头
typedef struct pcap_file_header_t{
    unsigned int magic;
    unsigned short int version_major;
    unsigned short int version_minor;
    unsigned int thiszone;
    unsigned int sigfigs;
    unsigned int snaplen;
    unsigned int linktype;
}PcapFileHeader_t;	//24bytes


// pcap包头
typedef struct pcap_pkt_header{
    unsigned int unGmtTime;
    unsigned int unMicroTime;
    unsigned int unCapLen;
    unsigned int unLen;
}PcapPktHeader_t;	//16bytes


// IP
typedef struct linux_ip_protocol_header
{
    unsigned char ucVersionAndHeaderLen;
    unsigned char ucServiceField;
    unsigned short usTotalLen;//124
    unsigned short usIdentification;
    unsigned short usFlagsAndFragment;
    unsigned char ucTimeToLive;
    unsigned char ucProtocol;
    unsigned short usHeaderChecksum;
    unsigned int  unSource;
    unsigned int  unDest;
}IpProtocolHeader_t; 	//20bytes

// UDP
typedef struct linux_udp_header{
    unsigned short usSrcPort;
    unsigned short usDestPort;
    unsigned short usLen;  //104
    unsigned short usChecksum;
}UdpHeader_t;         //8 bytes

// RTP
typedef struct rtp_header{
    unsigned char ucVersionPaddingExtendIdCount;
    unsigned char ucMarkerAndPayLoadType;
    unsigned short usSeq;
    unsigned int unTimeStamp;
    unsigned int unSyncSrcIdent;
}RtpHeader_t; //12bytes


// PCAP
typedef struct _pcap_obj
{
    FILE *fpOutput;
    char cFilenameArray[MAX_FILENAME_LEN];
}PcapObj;



// pcap文件读写函数
static int PcapOpen( const char *filename,PcapObj **ppcap );
static int PcapClose( PcapObj *pcap );
static int PcapWritePkt( PcapObj *pcap,char *ppkt,int len );

static void PcapInitFileHeader( PcapFileHeader_t *rpFileHeader );
static void PcapInitPktHeader( PcapPktHeader_t *rpPktHeader,int pktlen );

// 打印信息
static void PrintFileHeader(PcapFileHeader_t* rpFileHeader);
static void PrintPktHeader(PcapPktHeader_t* rpPktHeader);
static void PrintUdpHeader(UdpHeader_t* rpUdpHeader);
static void PrintIpHeader(IpProtocolHeader_t* rpIpHeader);

// 写数据包
bool AppendPkt( char *file,int count,char *buff,int len );


/**
 * 读取pcap文件并用UDP发包
 * @param nPkts 最大包数，0表示无限制
 * @param dstip 目的服务器
 */
int SendPcap( const char *fileName,uint32_t nPkts,char *dstip );


/**
 * @brief 追写pcap文件
 * @param file 文件名称，如kettas.pcap
 * @param count 采集包数目
 * @param buff 以太网帧
 * @param len 帧长度
 * 调用:("kettas.pcap",(char*)pdata,(unsigned int)(htons(iphead->Length)+14));
 */
bool AppendPkt( char *file,int count,char *buff,int len );



/// 打开pcap文件 
int PcapOpen( const char *filename,PcapObj **ppcap )
{
    PcapObj *pcap = NULL;
    FILE *fop = NULL;
    if(ppcap == NULL || filename == NULL)
        return -1;

    *ppcap = NULL;
    pcap = (PcapObj*)calloc(1,sizeof(PcapObj));
    if(pcap == NULL)
        return -2;

    if( (fop=fopen(filename,"wb")) )
    {
        pcap->fpOutput = fop;
        strncpy(pcap->cFilenameArray,filename,sizeof(pcap->cFilenameArray));
        *ppcap = pcap;

        // 初始化文件头
        PcapFileHeader_t fileHeader;
        PcapInitFileHeader( &fileHeader );
        fwrite( &fileHeader,sizeof(PcapFileHeader_t),1,pcap->fpOutput );

        return 0;
    }

    // 错误
    free(pcap);
    return -3;
}


// 关闭pcap文件
int PcapClose( PcapObj *pcap )
{
    if( pcap != NULL )
    {
        if(pcap->fpOutput)
        {
            fclose(pcap->fpOutput);
        }

        free(pcap);
        pcap = NULL;
    }

    return 0;
}


// 写入数据包，帧数据包
int PcapWritePkt( PcapObj *pcap,char *ppkt,int len )
{
    // 包头
    PcapPktHeader_t pktHeader;
    PcapInitPktHeader( &pktHeader,len );
    fwrite( &pktHeader,sizeof(PcapPktHeader_t),1,pcap->fpOutput);

    // 包数据
    fwrite( ppkt,len,1,pcap->fpOutput );
    fflush( pcap->fpOutput );
    return 0;
}


// pcap文件头初始化
void PcapInitFileHeader(PcapFileHeader_t* rpFileHeader)
{
    char* pmagic = (char*) (&rpFileHeader->magic);
    pmagic[0] = 0xd4;
    pmagic[1] = 0xc3;
    pmagic[2] = 0xb2;
    pmagic[3] = 0xa1;

    rpFileHeader->version_major = 2;
    rpFileHeader->version_minor = 4;
    rpFileHeader->thiszone = 0;
    rpFileHeader->sigfigs = 0;
    rpFileHeader->snaplen = UINT_MAX;
    rpFileHeader->linktype = 1;
}

// pcap包头初始化
void PcapInitPktHeader( PcapPktHeader_t *rpPktHeader,int pktlen )
{
    struct timeval ts;
    rpPktHeader->unCapLen = pktlen;
    rpPktHeader->unLen      = pktlen;
    gettimeofday(&ts,NULL);
    rpPktHeader->unGmtTime = (unsigned int)ts.tv_sec;
    rpPktHeader->unMicroTime = (unsigned int)ts.tv_usec;
}


// 打印文件头
void PrintFileHeader( PcapFileHeader_t* rpFileHeader )
{
    assert( rpFileHeader );
    printf( "magic:%x\n"
            "version_major:%d\n"
            "version_minor:%d\n"
            "timezone:%d\n"
            "snaplen:%d\n"
            "linktype:%d\n",
            rpFileHeader->magic,
            rpFileHeader->version_major,
            rpFileHeader->version_minor,
            rpFileHeader->thiszone,
            rpFileHeader->snaplen,
            rpFileHeader->linktype );
}


// 打印包头
void PrintPktHeader( PcapPktHeader_t* rpPktHeader )
{
    assert( rpPktHeader );
    printf( "gmt time:%lf\n"
            "caplen:%d\n"
            "len:%d\n",
            rpPktHeader->unGmtTime%60 + rpPktHeader->unMicroTime/1000000.0,
            rpPktHeader->unCapLen,
            rpPktHeader->unLen );
}


// 打印IP头
void PrintIpHeader(IpProtocolHeader_t* rpIpHeader)
{
    assert(rpIpHeader);
    printf( "total_len:0x%x\n"
            "protocol:0x%x\n",
            ntohs(rpIpHeader->usTotalLen),
            rpIpHeader->ucProtocol);
}


// 打印UDP头
void PrintUdpHeader(UdpHeader_t* rpUdpHeader)
{
    assert(rpUdpHeader);
    printf( "src_port:%d\n"
            "dest_port:%d\n"
            "len:%d\n",
            ntohs(rpUdpHeader->usSrcPort),
            ntohs(rpUdpHeader->usDestPort),
            ntohs(rpUdpHeader->usLen) );
}


// 读取pcap文件，并用原始套接字发送至服务器
int SendPcap( const char *fileName,uint32_t nPkts,char *dstip )
{
    PcapFileHeader_t file_header;
    PcapPktHeader_t pkt_header;

    unsigned long ulTotalCnt = 0;
    unsigned long ulTotalBytes  = 0;
    unsigned int count = 0;

    char buffer[2048];
    struct ip *iph;

    // UDP
    int m_sock = socket( AF_INET,SOCK_DGRAM,0 );

    struct sockaddr_in m_addr;
    memset( &m_addr, 0, sizeof(struct sockaddr_in) );
    m_addr.sin_family = AF_INET;
    m_addr.sin_port = htons(1813);
    inet_pton( AF_INET,dstip,&m_addr.sin_addr );

    // 读取PCAP文件
    FILE *fp = fopen(fileName,"rb");
    assert( fp != NULL );

    // PCAP头部
    int cnts = fread( &file_header,sizeof(PcapFileHeader_t),1,fp );

    while( !feof(fp) )
    {
        if( nPkts >0 && ulTotalCnt >= nPkts )
            break;

        // 包头
        memset(buffer,0,sizeof(buffer));
        cnts = fread( &pkt_header,sizeof(PcapPktHeader_t),1,fp );

        if( cnts == 1 )
        {
            // 包数据
            unsigned int bytes = fread( &buffer[0],sizeof(char),pkt_header.unCapLen,fp );
            if( bytes == pkt_header.unCapLen )
            {
                iph = (struct ip*)( buffer + sizeof(struct ethhdr) );
                char *data = NULL;
                int sLen = 0;

                // TCP/UDP的Data部分
                if( iph->ip_p == IPPROTO_TCP )
                {
                    data = (char*)iph + sizeof(struct ip) + sizeof(struct tcphdr);
                    sLen = htons( iph->ip_len ) - sizeof(struct ip) - sizeof(struct tcphdr); // tcp长度需计算
                }
                else if( iph->ip_p == IPPROTO_UDP )
                {
                    struct udphdr *udp = (struct udphdr*)((char*)iph + sizeof(struct ip));
                    data  = (char*)udp + sizeof(struct udphdr);
                    sLen = htons( udp->len ) - 8;	// udp长度包含头部
                }
                else
                {
                    continue;
                }

                // 用UDP方式发送，方便测试
                int len = sendto( m_sock,
                                  data,
                                  sLen,
                                  0,
                                  (struct sockaddr *)&m_addr,
                                  sizeof(struct sockaddr_in) );

                printf( "Seq:%d len:%d\n",++count,len );
                if( len > 0 )
                {
                    ulTotalCnt++;
                    ulTotalBytes += sizeof(PcapPktHeader_t) + pkt_header.unCapLen;
                }
            }
        }//if(cnts;)

        usleep(100);
    }//while(;)

    printf( "Total:%ldp Bytes:%ldB\n",
            ulTotalCnt,
            ulTotalBytes );

    fclose( fp );
    close( m_sock );
    return 0;
}


/**
 * @brief 写pcap文件
 * @param file 文件名称，如kettas.pcap
 * @param count 采集包数目
 * @param buff 以太网帧
 * @param len 帧长度
 * 调用:("kettas.pcap",(char*)pdata,(unsigned int)(htons(iphead->Length)+14))
 */
bool AppendPkt( char *file,int count,char *buff,int len )
{
    static PcapObj *pcap = NULL;
    static int pCount = 0;

    // 结束
    if( pCount && (pCount%count == 0) )
        return true;

    // 初始化
    if( pcap == NULL )
    {
        char path[100];
        sprintf( path,"/home/%s",file );
        PcapOpen( path,&pcap );
    }

    // 写内容
    if( len > 0 )
    {
        PcapWritePkt( pcap,buff,len );
        pCount++;
    }

    // 关闭
    if( pCount%count == 0 )
    {
        PcapClose( pcap );
        exit(1);
    }

    return true;
}

#endif	// _PCAP_OPER_H
