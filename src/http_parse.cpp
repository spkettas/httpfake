#include "http_parse.h"
#include <arpa/inet.h>

unsigned int BKDRHashUsername(char *str) {
  unsigned int seed = 131; // 31 131 1313 13131 131313 etc..
  unsigned int hash = 0;
  while (*str) {
    hash = hash * seed + (*str++);
  }

  return hash;
}

HttpParse::HttpParse() {
  m_PathMem = new MemPool<Pathlk>(4096, 100, 1);
  m_UrlMem = new MemPool<URLDetail>(4096, 100, 1);
}

HttpParse::~HttpParse() {
  if (m_UrlMem)
    delete m_UrlMem;

  if (m_PathMem)
    delete m_PathMem;
}

// ����http�ֶ�
bool HttpParse::parseHttp(char *data, int len, URLInfo *info) {
  if (data == NULL || len == 0 || info == NULL)
    return false;

  char *p = data;           // ԭʼ����
  unsigned char flag = 0x0; // ��ʶ����¼�����ֶ���
  unsigned int field = 0;   // �����ֶ�
  int j = 0;                // �������
  int vLen = 0;             // path��Ч����

  for (int i = 0; i < len; i++) {
    field = ntohl(*(unsigned int *)(p + i)); // ȡ�ֶε�intֵ������ƥ��
    switch (field) {
    case 0x47455420: // GET /front.js HTTP 1.1\r\n
    {
      if (i + 5 >= len)
        continue;

      i += 4; // offset

      // proxy server
      char *p1 = p + i;
      if ((p1[0] == 'h' && p1[1] == 't' && p1[2] == 't' && p1[3] == 'p') &&
          (p1[4] == ':' || p1[4] == 's')) // http: https:
        return false;

      if (p[i] != '/')
        return false;

      i++; // offset /

      j = 0;
      while (p[i] != '\r' && p[i] != '\0' && p[i] != ' ' &&
             j < MAX_PATHLEN - 1) {
        info->path[j++] = p[i];
        i++;
      }

      if (j > 0) {
        info->plen = j;
        info->path[j] = '\0';
      }

      vLen = info->plen;
      // xxx?ver=2.0
      char *qLoc = NULL;

      if ((qLoc = strstr(info->path, "?"))) {
        info->qLoc = qLoc + 1;
        //*qLoc = '\0';
        i++;

        vLen = qLoc - info->path;
      }

      // isHtml
      if ((vLen > 4) && (info->path[vLen - 1] == 'm') &&
          (info->path[vLen - 2] == 't') && (info->path[vLen - 3] == 'h') &&
          (info->path[vLen - 4] == '.')) {
        info->isHtml = true;
      }

      flag |= 0x01;
      break;
    }
    case 0x486F7374: // Host
    {
      if (i + 9 >= len)
        continue;

      i += 5; // offset host

      while (p[i] == 0x20)
        i++; // offset space

      j = 0;
      while (p[i] != '\r' && p[i] != '\0' && j < MAX_HOSTLEN - 1) {
        info->host[j++] = p[i];
        i++;
      }

      if (j > 0) {
        info->hlen = j;
        info->host[j] = '\0';
      }

      flag |= 0x02;
      break;
    }
    case 0x52656665: // refer
    {
      if (i + 20 >= len)
        continue;

      i += 8; // offset refer
      while (p[i] == 0x20)
        i++; // offset space

      if (p[i + 4] == ':') {
        i += 7; // offset http://
      } else if (p[i + 5] == ':') {
        i += 8; // offset https://
      } else {
        return false;
      }

      j = 0;
      while (p[i] != '/' && p[i] != '\r' && p[i] != '\0' &&
             j < MAX_HOSTLEN - 1) {
        info->refer[j++] = p[i]; // ѡȡ������������·��
        i++;
      }

      if (j > 0) {
        info->rlen = j;
        info->refer[j] = '\0';
      }

      flag |= 0x04;
      break;
    }
    case 0x55736572: // User-Agent
    {
      if (flag == (flag | 0x08)) // �ѻ�ȡ
        break;

      if (i + 12 >= len)
        break;

      i += 11; // offset ua
      while (p[i] == 0x20)
        i++; // offset space

      j = 0;
      while (p[i] != '\r' && p[i] != '\0' && j < MAX_UALEN - 1) {
        info->ua[j++] = p[i];
        i++;
      }

      flag |= 0x08;
      break;
    }
    default:
      break;
    } // switch()
  }   // for(;)

  return flag & 0x03; // ͨ����ʶ��¼��������
}

bool HttpParse::parseUrl(char *url, int len, char *host, char hlen) {
  bool isVague = false;

  char *slash = NULL;
  if ((slash = strstr(url, "/"))) // ȥ��·��/������������
  {
    *slash = '\0';
  }

  if (url[0] == '*') // ȥ��*
  {
    strcpy(host, url + 1);
    isVague = true;
  } else if (url[0] == 'h' && url[1] == 't' && url[2] == 't' && url[3] == 'p' &&
             url[4] == ':' && url[5] == '/' && url[6] == '/') // ȥ��http://
  {
    strncpy(host, url + 7, len - 7);
  } else {
    strcpy(host, url);
  }

  return isVague;
}

// �������
bool HttpParse::addUrl(char *url, int len, unsigned int taskid) {
  if (url == NULL || len == 0)
    return false;

  char prefix[MAX_HOSTLEN] = {};
  char host[MAX_HOSTLEN] = {};

  // ��ȡ������
  bool isVague = parseUrl(url, len, host, MAX_HOSTLEN);

  // ��������
  URLDetail *pUrl = FindUrl(host, len, NULL);
  if (pUrl == NULL) // ����������
  {
    pUrl = m_UrlMem->GetNode();
    if (pUrl == NULL) {
      printf("Out Of Memory\n");
      return false;
    }

    memset((void *)pUrl, 0, sizeof(URLDetail));
    char suffix[MAX_HOSTLEN] = {};

    // ���ǰ��׺
    splitUrl(host, strlen(host), suffix, prefix);

    if (strcmp(suffix, "") == 0)
      return false;

    strcpy(pUrl->suffix, suffix);
    pUrl->vague = isVague;
    m_HashDomain.insert(make_pair(BKDRHashUsername(suffix), pUrl));
  } else if (pUrl->vague) // ģ��ģʽ�����ʧ��
  {
    printf("Add url error in vague mode\n");
    return false;
  }

  // ��ȡǰ׺
  splitUrl(host, len, prefix, MAX_HOSTLEN);

  // ����������
  if (taskid == 0) {
    Pathlk *node = m_PathMem->GetNode();
    if (node == NULL) {
      printf("Out Of Memeory\n");
      return false;
    }

    memset((void *)node, 0, sizeof(Pathlk));
    strcpy(node->prefix, prefix);
    node->iswhite = true;

    if (pUrl) {
      pUrl->path = node;
    }

    return true;
  }

  Pathlk *pNode = pUrl->path;

  // �Ƿ����
  while (pNode) {
    if (!strcmp(pNode->prefix, prefix)) {
      // ���ڸ�����
      for (int i = 0; i < pNode->size; i++) {
        if (pNode->task[i] == taskid)
          return true;
      }

      pNode->task[pNode->size++] = taskid;
      return true;
    }

    pNode = pNode->next;
  } // while(pNode)

  // ׷������
  pNode = m_PathMem->GetNode();
  if (pNode == NULL) {
    printf("Out Of Memory\n");
    return false;
  }

  memset((void *)pNode, 0, sizeof(Pathlk));
  strcpy(pNode->prefix, prefix);
  pNode->task[pNode->size++] = taskid;
  pNode->next = pUrl->path;
  pUrl->path = pNode; // ����ͷ��

  return true;
}

// ɾ������
void HttpParse::delUrl(char *url, int len) {
  // ���ҹ�ϣ
  URLDetail *pUrl = FindUrl(url, len, NULL);

  Pathlk *lk = NULL;
  Pathlk *pTmp = NULL;

  // ֻ�ͷ�·��
  if (pUrl != NULL) {
    lk = pUrl->path;

    while (lk) {
      pTmp = lk;
      lk = lk->next;

      m_PathMem->FreeNode(pTmp);
      pTmp = NULL;
    }
  }

  pUrl->path = NULL;
}

void HttpParse::splitUrl(char *url, int len, char *prefix, int plen) {
  int count = 0;

  // ���ǰ׺
  for (int i = 0; i < len; i++) {
    switch (url[i]) {
    case '.': {
      count++;

      if (count == 1) {
        strncpy(prefix, url, i);
      }

      break;
    }
    default:
      break;
    }
  } // for(;)

  // ��ǰ׺���ÿ�
  if (count < 2) {
    bzero(prefix, plen);
  }
}

void HttpParse::splitUrl(char *url, int len, char *suffix, char *prefix) {
  int count = 0;

  // ���ǰ��׺
  for (int i = 0; i < len; i++) {
    switch (url[i]) {
    case '.': {
      count++;

      if (count == 1) {
        strncpy(prefix, url, i);
      }

      break;
    }
    default:
      break;
    }
  } // for(;)

  if (count == 1) {
    strcpy(suffix, url);
  } else if (count > 1) {
    strcpy(suffix, url + strlen(prefix) + 1);
  }
}

/// �����û����Ʋ�ѯ
URLDetail *HttpParse::FindUrl(char *url, int len, URLInfo *info) {
  if (url == NULL || len == 0)
    return NULL;

  char prefix[MAX_HOSTLEN] = {};
  char suffix[MAX_HOSTLEN] = {};

  // ���ǰ��׺
  splitUrl(url, len, suffix, prefix);

  // ��׺��ѯ
  hash_map<unsigned int, URLDetail *>::iterator it;
  it = m_HashDomain.find(BKDRHashUsername(suffix));

  if (it == m_HashDomain.end())
    return NULL;

  // �޽�����
  URLDetail *pUrl = it->second;
  if (info == NULL)
    return pUrl;

  Pathlk *lk = pUrl->path;
  if (pUrl->vague) // ģ��ģʽ
  {
    if (lk != NULL) {
      memcpy((void *)info->task, lk->task, sizeof(lk->task));
      info->count = lk->size;
      info->isWhite = lk->iswhite;
      info->isMatch = (strstr(info->host, pUrl->suffix) != NULL);
    }
  } else // ��ȷģʽ
  {
    while (lk) {
      if (!strcmp(lk->prefix, prefix)) {
        char whost[MAX_HOSTLEN];
        sprintf(whost,
                "%s%s%s", // A.B
                pUrl->path == NULL ? "" : pUrl->path->prefix,
                pUrl->path == NULL ? "" : ".", pUrl->suffix);

        memcpy((void *)info->task, lk->task, sizeof(lk->task));
        info->count = lk->size;
        info->isWhite = lk->iswhite;
        info->isMatch = (strcmp(info->host, whost) == 0);
        break;
      }

      lk = lk->next;
    } // while()
  }   // else()

  return pUrl;
}

// ��������������
bool HttpParse::cmpUrl(URLInfo *info) {
  return (info == NULL)
             ? false
             : (FindUrl(info->host, strlen(info->host), info) != NULL);
}

bool HttpParse::formatTasks(Pathlk *pNode, char *szbuf, int len) {
  bzero(szbuf, len);

  if (pNode == NULL)
    return false;

  int pLen = 0, offset = 0;
  for (int i = 0; i < pNode->size; i++) {
    pLen = sprintf(szbuf + offset, "%d|", pNode->task[i]);
    offset += pLen;
  }

  return true;
}
