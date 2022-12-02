#include "packet_sniffer.h"
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>

/**
 * @brief 测试入口
 * 本例演示http劫持技术原理，仅拦截指定源IP且路径长度为25的请求，可依实际情况修改
 *
 * 注：尊重数据安全，请勿用于非法之目的
 */
int main(int argc, char **argv) {
  if (argc < 4) {
    printf("Usage:%s eth0 type ip\n", basename(argv[0]));
    printf("       eth0 The nic will be collect\n");
    printf("       type How to collect traffic；1.rawsocket 2.libpcap\n");

    return 1;
  }

  // 采集类
  PacketSniffer pSniffer;
  pSniffer.Start(argv[1], atoi(argv[2]));

  return 0;
}
