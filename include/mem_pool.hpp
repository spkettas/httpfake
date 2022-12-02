template <typename DataType>
MemPool<DataType>::MemPool(unsigned int PageSize, unsigned int MaxPage,
                           int Mode) {
  m_PageSize = PageSize;
  m_PageCnt = MaxPage * 2;
  m_Mode = Mode;

  // for record page block addr
  m_PageAddr = new DataType *[m_PageCnt];
  if (m_PageAddr == NULL) {
    printf("Fatal Error!can't initialize memory\n");
    return;
  }
  memset(m_PageAddr, 0, m_PageCnt * sizeof(DataType *));
  // reusable mode
  if (m_Mode == REUSABLE_MODE) {
    m_ListAddr = new PAGE_STRUCT *[m_PageCnt];
    if (m_ListAddr == NULL) {
      printf("Fatal Error!can't initialize memory\n");
      delete[] m_PageAddr;
      return;
    }
    memset(m_ListAddr, 0, m_PageCnt * sizeof(PAGE_STRUCT *));
    // allocat link struct memory
    m_Head = new PAGE_STRUCT[m_PageSize];
    if (m_Head == NULL) {
      printf("Fatal Error!can't initialize memory\n");
      delete[] m_PageAddr;
      delete[] m_ListAddr;
      return;
    }
    memset(m_Head, 0, sizeof(PAGE_STRUCT) * m_PageSize);
    m_ListAddr[0] = m_Head;
    // printf("It take %ubytes additional memory for management\n",
    // sizeof(PAGE_STRUCT)*m_PageSize+m_PageCnt*sizeof(PAGE_STRUCT *));
  }
  m_PageAddr[0] = new DataType[m_PageSize];
  if (m_PageAddr[0] == NULL) {
    printf("Fatal Error!can't initialize memory\n");
    delete[] m_PageAddr;
    if (m_Mode == REUSABLE_MODE) {
      delete[] m_ListAddr;
      delete[] m_ListAddr[0];
    }
    return;
  }
  memset(m_PageAddr[0], 0, m_PageSize * sizeof(DataType));

  if (m_Mode == REUSABLE_MODE) {
    // setup free list;
    for (unsigned int j = 0; j < m_PageSize - 1; j++) {
      m_Head[j].addr = m_PageAddr[0] + j;
      m_Head[j].next = m_Head + j + 1;
    }
    m_Head[m_PageSize - 1].addr = m_PageAddr[0] + m_PageSize - 1;
    m_Head[m_PageSize - 1].next = m_Head;
    m_Free = m_Head;
    // m_Tail=m_Head+m_PageSize-1;
  }
  m_cur = 0;
  m_curpage = 0;
  m_curlist = 0;
  m_freecnt = m_PageSize;

  // printf("Allocate %ubytes memory for user stat!total
  // node=%d\n",m_PageSize*sizeof(DataType),m_PageSize);
}

template <typename DataType> MemPool<DataType>::~MemPool() {
  for (unsigned int i = 0; i <= m_curpage; i++) {
    delete[] m_PageAddr[i];
  }

  delete[] m_PageAddr;
  if (m_Mode == REUSABLE_MODE) {
    for (unsigned int i = 0; i < m_curlist; i++) {
      delete[] m_ListAddr[i];
    }
    delete[] m_ListAddr;
  }
}

template <typename DataType> bool MemPool<DataType>::append() {
  if (m_curpage > m_PageCnt - 2) {
    printf("Reach Max page number, can't allocat mem!\n");
    return false;
  }
  m_PageAddr[m_curpage + 1] = new DataType[m_PageSize / 2];
  if (m_PageAddr[m_curpage + 1] == NULL) {
    printf("Fatal Error!can't append the stat memory\n");
    return false;
  }
  memset(m_PageAddr[m_curpage + 1], 0, m_PageSize / 2 * sizeof(DataType));

  if (m_Mode == REUSABLE_MODE) {
    m_ListAddr[m_curpage + 1] = new PAGE_STRUCT[m_PageSize / 2];
    if (m_ListAddr[m_curpage + 1] == NULL) {
      printf("Fatal Error!can't initialize the stat memory\n");
      return false;
    }
    memset(m_ListAddr[m_curpage + 1], 0, sizeof(PAGE_STRUCT) * m_PageSize / 2);

    PAGE_STRUCT *_head = m_ListAddr[m_curpage + 1];
    PAGE_STRUCT *begin = _head;
    for (unsigned int j = 0; j < m_PageSize / 2 - 1; j++) {
      _head[j].addr = m_PageAddr[m_curpage + 1] + j;
      _head[j].next = m_ListAddr[m_curpage + 1] + j + 1;
      // m_Free=m_Free->next;
    }
    _head[m_PageSize / 2 - 1].addr =
        m_PageAddr[m_curpage + 1] + m_PageSize / 2 - 1;
    _head[m_PageSize / 2 - 1].next = m_Head->next;
    m_Head->next = begin;
    // printf("It take %ubytes additional memory for
    // management\n",m_PageSize/2*sizeof(PAGE_STRUCT));
  }
  m_cur = 0;
  m_curpage++;
  m_freecnt += m_PageSize / 2;
  // printf("Append %ubytes memory for user stat!add
  // node=%d\n",m_PageSize/2*sizeof(DataType),m_PageSize/2);
  return true;
}

template <typename DataType> DataType *MemPool<DataType>::GetNode() {
  DataType *pmem = NULL;

  if (m_Mode == REUSABLE_MODE) {
    if (m_Head->next == m_Free) {
      if (!append())
        return NULL;
    }
    pmem = m_Head->addr;
    m_Head->addr = NULL;
    m_Head = m_Head->next;
  } else {
    if ((m_cur == m_PageSize && m_curpage == 0) ||
        (m_cur == m_PageSize / 2 && m_curpage > 0)) {
      if (!append())
        return NULL;
    }
    pmem = m_PageAddr[m_curpage] + m_cur++;
  }
  m_freecnt--;
  return pmem;
}

template <typename DataType>
bool MemPool<DataType>::FreeNode(DataType *pmdstat) {
  // if(m_curlist>0)
  //	printf("Free begin!\n");

  if (m_Mode != REUSABLE_MODE || NULL == pmdstat)
    return false;
  /*
          if(m_Free==m_Head)
          {
                  //m_Tail=m_Free;

                  //m_ListAddr[m_curlist+1]= new PAGE_STRUCT[m_PageSize/2];
                  //if(m_ListAddr[m_curlist+1]==NULL)
                  //{
                  //	printf("Fatal Error!can't initialize the stat
     memory\n");
                  //	return false;
                  //}
                  //memset(m_ListAddr[m_curlist+1],0,sizeof(PAGE_STRUCT)*m_PageSize/2);

                  m_Free=m_ListAddr[m_curlist+1];
                  for(unsigned int i=0;i<m_PageSize/2-1;i++)
                  {
                          m_Free[i].next=m_ListAddr[m_curlist+1]+i+1;
                          //m_Free=m_Free->next;
                  }
                  m_Free[m_PageSize/2-1].next=m_Head;
                  m_Free=m_ListAddr[m_curlist+1];
                  //m_Free=m_Tail;

                  m_curlist++;
          }
  */

  //	memset(pmdstat, 0, sizeof(DataType));
  //	m_Free->addr=pmdstat;
  m_Free->addr = pmdstat;
  m_Free = m_Free->next;
  m_freecnt++;
  // if(m_curlist>0)
  //	printf("Free OK!\n");
  return true;
}

template <typename DataType> bool MemPool<DataType>::IsEmpty() {
  return (m_freecnt == m_PageSize + (m_curpage)*m_PageSize / 2);
}

template <typename DataType> bool MemPool<DataType>::IsFull() {
  return (m_freecnt == 0);
}

template <typename DataType> unsigned int MemPool<DataType>::UsedNodesCount() {
  // TODO
  return m_PageSize + (m_curpage)*m_PageSize / 2 - m_freecnt;
}

template <typename DataType> unsigned int MemPool<DataType>::NodesCount() {
  // TODO
  return m_PageSize + (m_curpage)*m_PageSize / 2;
}

template <typename DataType> unsigned int MemPool<DataType>::FreeNodesCount() {
  // TODO
  return m_freecnt;
}

template <typename DataType> void MemPool<DataType>::SetZero() {}

template <typename DataType> void MemPool<DataType>::Reset() {
  unsigned int i = 0;
  if (m_Mode == REUSABLE_MODE) {
    // setup free list;
    for (i = 0; i < m_PageSize - 1; i++) {
      m_Head[i].addr = m_PageAddr[0] + i;
      m_Head[i].next = m_Head + i + 1;
    }
    m_Head[m_PageSize - 1].addr = m_PageAddr[0] + m_PageSize - 1;
    m_Head[m_PageSize - 1].next = m_Head;
    m_Free = m_Head;

    for (i = 1; i <= m_curlist; i++) {
      delete[] m_ListAddr[i];
    }
  }

  for (i = 1; i <= m_curpage; i++) {
    delete[] m_PageAddr[i];
  }
  m_cur = 0;
  m_curpage = 0;
  m_freecnt = m_PageSize;
  m_curlist = 0;
}
