#ifndef _HTTP_FAKE_H_
#define _HTTP_FAKE_H_

#include <netinet/in.h>
#include <sys/types.h>

/**
 * @brief HTTP伪造响应类
 *
 */
class HttpFake {
public:
  HttpFake();
  ~HttpFake();

  /**
   * @brief 发送HTTP响应
   * @param ip  自IP头部起数据包
   * @param respone HTML响应字段
   * @return 发送状态
   */
  bool sendHttpResponse(char *buff, char *response);

private:
  int m_rawsock;             // 原始套接字
  struct sockaddr_in m_addr; // 地址

#define PACKET_BUFFER_LEN 2000
  char PacketBuffer[PACKET_BUFFER_LEN]; ///< 整个包的缓冲区
};

#endif // _HTTP_FAKE_H_
