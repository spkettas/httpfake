#ifndef _MEM_POOL_H_
#define _MEM_POOL_H_

#include <assert.h>
#include <stdio.h>
#include <string.h>

#define REUSABLE_MODE 1

using namespace std;

/**
 * @brief 内存池，设计比较糟糕，后期重新设计
 *
 */
template <typename DataType> class MemPool {
public:
  MemPool(unsigned int PageSize, unsigned int MaxPage, int Mode);
  ~MemPool();
  // bool init();
  DataType *GetNode();
  bool FreeNode(DataType *pmdstat);
  bool IsEmpty();
  bool IsFull();
  unsigned int NodesCount();
  unsigned int UsedNodesCount();
  unsigned int FreeNodesCount();
  void Reset();
  void SetZero();

private:
  bool append();

protected:
private:
  int m_Mode;
  unsigned int m_PageSize;
  unsigned int m_PageCnt;
  unsigned int m_cur;
  unsigned int m_curpage;
  unsigned int m_curlist;
  unsigned int m_freecnt;

  struct PAGE_STRUCT {
    DataType *addr;
    PAGE_STRUCT *next;
  };

  ///< 空闲节点的下标
  PAGE_STRUCT **m_ListAddr;
  PAGE_STRUCT *m_Head;
  PAGE_STRUCT *m_Free;
  PAGE_STRUCT *m_Tail;

  DataType **m_PageAddr;
  DataType *m_addr;
};

#include "./mem_pool.hpp"

#endif // _MEM_POOL_H_
