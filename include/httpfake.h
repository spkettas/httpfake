#ifndef _HTTP_FAKE_H_
#define _HTTP_FAKE_H_

#include <netinet/in.h>
#include <sys/types.h>

/**
 * @brief HTTPα����Ӧ��
 *
 */
class HttpFake {
public:
  HttpFake();
  ~HttpFake();

  /**
   * @brief ����HTTP��Ӧ
   * @param ip  ��IPͷ�������ݰ�
   * @param respone HTML��Ӧ�ֶ�
   * @return ����״̬
   */
  bool sendHttpResponse(char *buff, char *response);

private:
  int m_rawsock;             // ԭʼ�׽���
  struct sockaddr_in m_addr; // ��ַ

#define PACKET_BUFFER_LEN 2000
  char PacketBuffer[PACKET_BUFFER_LEN]; ///< �������Ļ�����
};

#endif // _HTTP_FAKE_H_
