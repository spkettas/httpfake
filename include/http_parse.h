#ifndef _HTTP_PARSE_H
#define _HTTP_PARSE_H

#include "mem_pool.h"
#include <ext/hash_map>


using namespace __gnu_cxx;

#define MAX_HOSTLEN 60
#define MAX_PATHLEN 256
#define MAX_UALEN 128
#define MAX_BIND_TASK 10 // 最大绑定10个任务

/**
 * 域名结构体
 */
typedef struct {
  char host[MAX_HOSTLEN];  // 主域名
  int hlen;                // host length
  char path[MAX_PATHLEN];  // 请求文件名称
  int plen;                // path length，以空间换时间
  char refer[MAX_HOSTLEN]; // refer
  int rlen;                // refer length
  char ua[MAX_UALEN];      // UserAgent
  char *qLoc;              // 刷新部分

  unsigned int task[MAX_BIND_TASK]; // 任务列表
  int count;                        // 任务个数

  bool isHtml;  // 是否为html
  bool isWhite; // 是否为白名单
  bool isMatch; // 域名是否匹配
} URLInfo;

/**
 * 任务列表，链表结构。因涉及到模糊匹配，必须按前后缀拆分域名，优化存储空间。
 *
 */
typedef struct _Pathlk {
  unsigned int task[MAX_BIND_TASK]; // 任务列表
  char size;                        // 任务数目
  bool iswhite;                     // 是否为白名单
  char prefix[MAX_HOSTLEN];         // 前缀，如www
  _Pathlk *next;                    // 路径指针
} Pathlk;

/**
 * 内部储存的URL结构体
 *
 */
typedef struct {
  char suffix[MAX_HOSTLEN]; // 后缀，如baidu.com
  bool vague;               // 是否启用模糊匹配
  Pathlk *path;             // 路径链表
} URLDetail;

/**
 * @brief HTTP报文解析类,全面取代push_urlmatch
 *
 */
class HttpParse {
public:
  HttpParse();
  ~HttpParse();

  // 解析http字段
  bool parseHttp(char *data, int len, URLInfo *info);

  // 处理域名,去除http:// / *字符，返回是否模糊标志
  bool parseUrl(char *url, int len, char *host, char hlen);

  // 添加域名，白名单taskid=0
  bool addUrl(char *url, int len, unsigned int taskid);
  // 删除域名
  void delUrl(char *url, int len);

  // URL查询，结果存入info，只匹配主域名
  URLDetail *FindUrl(char *url, int len, URLInfo *info);

  // 拆分url
  void splitUrl(char *url, int len, char *prefix, int plen);
  void splitUrl(char *url, int len, char *suffix, char *prefix);

  // 查找域名绑定任务
  bool cmpUrl(URLInfo *info);

private:
  // 格式化任务列表
  bool formatTasks(Pathlk *pNode, char *szbuf, int len);

private:
  MemPool<URLDetail> *m_UrlMem;
  MemPool<Pathlk> *m_PathMem;
  hash_map<unsigned int, URLDetail *> m_HashDomain; // 域名组
};

#endif // _HTTP_PARSE_H
