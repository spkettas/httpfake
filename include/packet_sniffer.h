#ifndef _PACKET_SNIFFER_H_
#define _PACKET_SNIFFER_H_

/**
 * @brief The PacketSniffer class
 *
 * Sniffer net packet by Raw socket or Libpcap
 */
class HttpParse;
class HttpFake;
class PacketSniffer {
public:
  PacketSniffer();
  ~PacketSniffer();

  /**
   * @brief 启动采集
   * @param eth  采集网卡
   * @param type 采集类型，1.原始套接字 2.libpcap
   *
   */
  void Start(char *eth, int type);

  // 处理数据包
  void HandleFrame(char *pdata);

private:
  // 原始套接字采集
  void RawSniffer(const char *eth);
  // Pcap采集
  void PcapSniffer(char *eth);

private:
  HttpParse *mParser;       // http解析类
  HttpFake *mFaker;         // http伪造类
  unsigned int m_PreventIp; // 拦截IP
};

#endif // _PACKET_SNIFFER_H_
