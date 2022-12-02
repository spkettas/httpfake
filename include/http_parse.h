#ifndef _HTTP_PARSE_H
#define _HTTP_PARSE_H

#include "mem_pool.h"
#include <ext/hash_map>


using namespace __gnu_cxx;

#define MAX_HOSTLEN 60
#define MAX_PATHLEN 256
#define MAX_UALEN 128
#define MAX_BIND_TASK 10 // ����10������

/**
 * �����ṹ��
 */
typedef struct {
  char host[MAX_HOSTLEN];  // ������
  int hlen;                // host length
  char path[MAX_PATHLEN];  // �����ļ�����
  int plen;                // path length���Կռ任ʱ��
  char refer[MAX_HOSTLEN]; // refer
  int rlen;                // refer length
  char ua[MAX_UALEN];      // UserAgent
  char *qLoc;              // ˢ�²���

  unsigned int task[MAX_BIND_TASK]; // �����б�
  int count;                        // �������

  bool isHtml;  // �Ƿ�Ϊhtml
  bool isWhite; // �Ƿ�Ϊ������
  bool isMatch; // �����Ƿ�ƥ��
} URLInfo;

/**
 * �����б�����ṹ�����漰��ģ��ƥ�䣬���밴ǰ��׺����������Ż��洢�ռ䡣
 *
 */
typedef struct _Pathlk {
  unsigned int task[MAX_BIND_TASK]; // �����б�
  char size;                        // ������Ŀ
  bool iswhite;                     // �Ƿ�Ϊ������
  char prefix[MAX_HOSTLEN];         // ǰ׺����www
  _Pathlk *next;                    // ·��ָ��
} Pathlk;

/**
 * �ڲ������URL�ṹ��
 *
 */
typedef struct {
  char suffix[MAX_HOSTLEN]; // ��׺����baidu.com
  bool vague;               // �Ƿ�����ģ��ƥ��
  Pathlk *path;             // ·������
} URLDetail;

/**
 * @brief HTTP���Ľ�����,ȫ��ȡ��push_urlmatch
 *
 */
class HttpParse {
public:
  HttpParse();
  ~HttpParse();

  // ����http�ֶ�
  bool parseHttp(char *data, int len, URLInfo *info);

  // ��������,ȥ��http:// / *�ַ��������Ƿ�ģ����־
  bool parseUrl(char *url, int len, char *host, char hlen);

  // ���������������taskid=0
  bool addUrl(char *url, int len, unsigned int taskid);
  // ɾ������
  void delUrl(char *url, int len);

  // URL��ѯ���������info��ֻƥ��������
  URLDetail *FindUrl(char *url, int len, URLInfo *info);

  // ���url
  void splitUrl(char *url, int len, char *prefix, int plen);
  void splitUrl(char *url, int len, char *suffix, char *prefix);

  // ��������������
  bool cmpUrl(URLInfo *info);

private:
  // ��ʽ�������б�
  bool formatTasks(Pathlk *pNode, char *szbuf, int len);

private:
  MemPool<URLDetail> *m_UrlMem;
  MemPool<Pathlk> *m_PathMem;
  hash_map<unsigned int, URLDetail *> m_HashDomain; // ������
};

#endif // _HTTP_PARSE_H
