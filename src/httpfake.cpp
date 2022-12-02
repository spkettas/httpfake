#include "httpfake.h"
#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define PACKET_BUFFER_LEN 2000

// HTTP头部
#define HTTP_HEAD                                                              \
  "HTTP/1.1 200 OK\r\n"                                                        \
  "Server: Apache/2.0.43\r\n"                                                  \
  "Content-Type: text/html\r\n"                                                \
  "Expires: -1000\r\n"                                                         \
  "Cache-Control: no-cache\r\n"                                                \
  "Access-Control-Allow-Origin: *\r\n"                                         \
  "Connection: close\r\n"                                                      \
  "Date: Sun, 00 Jan 1900 00:00:00 GMT\r\n"                                    \
  "Content-Length: "

unsigned short CheckSum(unsigned short *buffer, int size);
int IPCheckSum(iphdr *ip);

///
HttpFake::HttpFake() {
  memset(&m_addr, 0, sizeof(struct sockaddr_in));
  m_addr.sin_family = AF_INET;

  m_rawsock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  assert(m_rawsock > 0);

  int nValue = 1;
  int flag = setsockopt(m_rawsock, IPPROTO_IP, IP_HDRINCL,
                        (const char *)&nValue, sizeof(nValue));
  assert(flag == 0);
}

HttpFake::~HttpFake() {
  if (m_rawsock > 0) {
    close(m_rawsock);
  }
}

bool HttpFake::sendHttpResponse(char *buff, char *response) {
  struct iphdr *ip = (struct iphdr *)buff;
  struct tcphdr *tcp = (struct tcphdr *)((char *)buff + sizeof(struct iphdr));

  int nHeadLen = ip->ihl * 4 + tcp->doff * 4;
  int Length = htons(ip->tot_len) - ip->ihl * 4 - tcp->doff * 4;

  char *pPacketBuffer = this->PacketBuffer;
  memset((void *)pPacketBuffer, 0, PACKET_BUFFER_LEN);

  // 添加html
  char *ContentBuffer = pPacketBuffer + 350;
  int nContentLen = snprintf(ContentBuffer, 1300, response);

  // 内容长度
  char strLen[25];
  int cLen = sprintf(strLen, "%d\r\n\r\n", nContentLen);

  /*
   * nHeadLen(iphead +tcphead) + http_head + content_length + content
   */
  pPacketBuffer = ContentBuffer - (nHeadLen + sizeof(HTTP_HEAD) - 1 + cLen);
  memcpy(pPacketBuffer, ip, nHeadLen);
  memcpy(pPacketBuffer + nHeadLen, HTTP_HEAD, sizeof(HTTP_HEAD));
  memcpy(pPacketBuffer + nHeadLen + sizeof(HTTP_HEAD) - 1, strLen, cLen);

  // IP
  struct iphdr *pTempIP = (struct iphdr *)pPacketBuffer;
  pTempIP->version = 4;
  pTempIP->ihl = 5;
  pTempIP->protocol = IPPROTO_TCP;
  pTempIP->saddr = ip->daddr;
  pTempIP->daddr = ip->saddr;

  // TCP
  struct tcphdr *pTempTcp =
      (struct tcphdr *)((char *)pTempIP + sizeof(struct iphdr));
  if (pTempTcp == NULL) {
    printf("%s\n", "TCP NULL");
    return false;
  }

  pTempTcp->source = tcp->dest;
  pTempTcp->dest = tcp->source;
  pTempTcp->seq = tcp->ack_seq;
  pTempTcp->ack_seq = ntohl(ntohl(tcp->seq) + Length);
  pTempTcp->ack = 1;
  pTempTcp->fin = 0;
  pTempTcp->psh = 1;

  // 校验和
  int nLen = nHeadLen + sizeof(HTTP_HEAD) - 1 + cLen + nContentLen;
  pTempIP->tot_len = htons(nLen);
  IPCheckSum(pTempIP);

  // IPv4发送
  m_addr.sin_addr.s_addr = pTempIP->daddr;
  int count = sendto(m_rawsock, (const char *)pTempIP, ntohs(pTempIP->tot_len),
                     0, (struct sockaddr *)&m_addr, sizeof(struct sockaddr_in));

  return count > 0;
}

#ifndef PACK
#define PACK __attribute__((packed))
#endif

typedef struct CheckSumHeader {
  unsigned int SrcIP;    ///< 源IP
  unsigned int DestIP;   ///< 目的IP
  char Zero;             ///< 填充部分
  char Protocol;         ///< 协议
  unsigned short Length; ///< 长度
} PACK CheckSumHeader;

// 检验和
unsigned short CheckSum(unsigned short *buffer, int size) {
  unsigned long cksum = 0;
  while (size > 1) {
    cksum += *buffer++;
    size -= sizeof(unsigned short);
  }

  if (size) {
    cksum += *(unsigned char *)buffer;
  }

  cksum = (cksum >> 16) + (cksum & 0xffff);
  cksum += (cksum >> 16);
  return (unsigned short)(~cksum);
}

// IP检验和
int IPCheckSum(iphdr *ip) {
  if (NULL == ip || 4 != ip->version || 5 > ip->ihl) {
    return -1;
  }

  unsigned char protocol = ip->protocol;
  if (!(protocol == IPPROTO_TCP || protocol == IPPROTO_UDP)) {
    ip->check = 0;
    ip->check = CheckSum((unsigned short *)ip, sizeof(struct iphdr));
    return 0;
  }

  // 计算伪首部
  char *ipdata = (char *)ip + ip->ihl * 4;
  CheckSumHeader *check = (CheckSumHeader *)(ipdata - sizeof(CheckSumHeader));

  char temp[sizeof(CheckSumHeader)];
  memcpy(temp, check, sizeof(CheckSumHeader));
  check->SrcIP = ip->saddr;
  check->DestIP = ip->daddr;
  check->Zero = 0;
  check->Protocol = protocol;
  check->Length = ntohs(ntohs(ip->tot_len) - sizeof(struct iphdr));

  if (protocol == IPPROTO_TCP) {
    struct tcphdr *tcp = (struct tcphdr *)ipdata;
    tcp->check = 0;
    tcp->check = CheckSum((unsigned short *)check, ntohs(ip->tot_len) -
                                                       sizeof(struct ip) +
                                                       sizeof(CheckSumHeader));
  } else if (protocol == IPPROTO_UDP) {
    struct udphdr *udp = (struct udphdr *)ipdata;
    udp->check = 0;
    udp->check = CheckSum((unsigned short *)check, ntohs(ip->tot_len) -
                                                       sizeof(struct ip) +
                                                       sizeof(CheckSumHeader));
  }

  memcpy(check, temp, sizeof(CheckSumHeader));

  // 计算IP校验和
  ip->check = 0;
  ip->check = CheckSum((unsigned short *)ip, sizeof(struct iphdr));
  return 0;
}
