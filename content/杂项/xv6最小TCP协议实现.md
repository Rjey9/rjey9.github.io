---
draft: true
---
### xv6简介

### 开始前需要做的一些准备

将`makefile`中的cpu数设置为1，避免多核调试带来的一些潜在问题。

```c
ifndef CPUS
CPUS := 1
endif
ifeq ($(LAB),fs)
CPUS := 1
endif
```
### xv6的tcp实现

在xv6中实现了针对e1000网卡的相应驱动，由于我们主要关注网络协议栈，对该部分底层内容暂时不做讲解。

在驱动从网卡中提取数据包后，向cpu发起中断，操作系统开始处理到达的以太网数据包，此时会经历的函数调用链处理：

![](杂项/images/XV6net/xv6netfuncs.png)

基于已有的网络实现，我们可以实现一个最小TCP协议，其基本结构如下：

![](杂项/images/XV6net/tcp.png)

#### tcp实现

首先在`kernel/net.h`中定义tcp报文的相关数据结构：

```c
struct tcp {
  uint16 sport;       // 源端口
  uint16 dport;       // 目的端口
  uint32 seq;         // 序列号
  uint32 ack;         // 确认号
  uint8  off;         // 首部长度（高4位），保留（低4位）
  uint8  flags;       // 标志位（SYN/ACK/FIN等）
  uint16 window;      // 窗口大小
  uint16 cksum;       // 校验和
  uint16 urgptr;      // 紧急指针
} __attribute__((packed));
```

然后再在`net.c`中实现tcp相关的函数。

首先是`net_rx_ip`函数，需要向其中添加tcp相关的处理

```c
static void
net_rx_ip(struct mbuf *m)
{
  struct ip *iphdr;

  iphdr = mbufpullhdr(m, *iphdr);
  if (!iphdr)
    goto fail;

  // 检查 IP 版本和头部长度
  if (iphdr->ip_vhl != ((4 << 4) | (20 >> 2)))
    goto fail;

  // 验证 IP 校验和
  if (in_cksum((unsigned char *)iphdr, sizeof(*iphdr)))
    goto fail;

  // 不支持分片
  if (htons(iphdr->ip_off) != 0)
    goto fail;

  // 检查目标 IP 是否是本地 IP
  if (htonl(iphdr->ip_dst) != local_ip)
    goto fail;

  // 根据协议类型分发：udp/tcp
  if (iphdr->ip_p == IPPROTO_UDP) {
    net_rx_udp(m, ntohs(iphdr->ip_len) - sizeof(*iphdr), iphdr);
  } else if (iphdr->ip_p == IPPROTO_TCP) {
    net_rx_tcp(m, ntohs(iphdr->ip_len) - sizeof(*iphdr), iphdr); // 添加对 TCP 的处理
  } else {
    goto fail;
  }
  return;

fail:
  mbuffree(m);
}
```

然后是分别实现`net_rx_tcp`与`net_tx_tcp`，前者用于tcp数据包的接收处理；后者用于tcp数据包的发送处理。

```c
//接收到tcp报文
static void
net_rx_tcp(struct mbuf *m, uint16 len, struct ip *iphdr)
{
  struct tcp *tcphdr;
  uint32 sip;
  uint16 sport, dport;

  // 提取 TCP 报头
  tcphdr = mbufpullhdr(m, *tcphdr);
  if (!tcphdr)
    goto fail;

  // 验证 TCP 校验和（可选，简化时可以跳过）
  // uint16 checksum = tcp_checksum(tcphdr, iphdr->ip_src, iphdr->ip_dst, m->head, len);
  // if (checksum != 0)
  //   goto fail;

  // 提取源 IP 和端口
  sip = ntohl(iphdr->ip_src);
  sport = ntohs(tcphdr->sport);
  dport = ntohs(tcphdr->dport);

  // 调用 TCP 协议栈处理函数
  tcp_input(m, sip, sport, dport, tcphdr);
  return;

fail:
  mbuffree(m);
}

//发送tcp报文
void
net_tx_tcp(struct mbuf *m, uint32 dip, uint16 sport, uint16 dport)
{
  struct tcp *tcphdr;

  // push TCP header
  tcphdr = mbufpushhdr(m, *tcphdr);
  memset(tcphdr, 0, sizeof(*tcphdr));
  tcphdr->sport = htons(sport);
  tcphdr->dport = htons(dport);
  // 下面这些字段由调用者设置（如 SYN/ACK/SEQ/ACK/flags/window），
  // 这里只是默认初始化，实际用时调用者会覆盖
  // tcphdr->seq = htonl(0);
  // tcphdr->ack = htonl(0);
  // tcphdr->off = (sizeof(struct tcp) / 4) << 4;
  // tcphdr->flags = 0;
  // tcphdr->window = htons(65535);
  tcphdr->cksum = 0; // 暂不计算校验和
  tcphdr->urgptr = 0;

  // 交给 IP 层发送
  net_tx_ip(m, IPPROTO_TCP, dip);
}
```

最后是关键的tcp_input函数，该函数用于处理tcp报文

```c
void tcp_input(struct mbuf *m, uint32 sip, uint16 sport, uint16 dport, struct tcp *tcphdr)
{
    // 1. 解析 TCP 头部长度
    int tcphdr_len = ((tcphdr->off >> 4) & 0xF) * 4;
    if (tcphdr_len < sizeof(struct tcp)) {
        // 非法 TCP 头部
        mbuffree(m);
        return;
    }

    // 2. 解析标志位
    uint8 flags = tcphdr->flags;

    // 3. 打印调试信息
    printf("tcp_input: sip=%x sport=%d dport=%d seq=%u ack=%u flags=0x%x\n",
           sip, sport, dport, ntohl(tcphdr->seq), ntohl(tcphdr->ack), flags);

    // 4. 这里只做简单的 SYN 处理
    if (flags & 0x02) { // SYN
        // 这里应该查找是否有监听该端口的 socket
        // 假设我们总是回复 SYN+ACK
        struct mbuf *reply = mbufalloc(MBUF_DEFAULT_HEADROOM);
        if (!reply) {
            mbuffree(m);
            return;
        }

        // 填充 TCP 头部
        struct tcp *reply_tcp = mbufputhdr(reply, *reply_tcp);
        memset(reply_tcp, 0, sizeof(*reply_tcp));
        reply_tcp->sport = htons(dport);
        reply_tcp->dport = htons(sport);
        reply_tcp->seq = htonl(0); // 初始序列号
        reply_tcp->ack = htonl(ntohl(tcphdr->seq) + 1);
        reply_tcp->off = (sizeof(struct tcp) / 4) << 4;
        reply_tcp->flags = 0x12; // SYN+ACK
        reply_tcp->window = htons(65535);

        // 计算校验和（可选，实验可先设为0）
        reply_tcp->cksum = 0;

        // 发送 TCP 报文（需要实现 net_tx_tcp，类似 net_tx_udp）
        net_tx_tcp(reply, sip, dport, sport);

        printf("tcp_input: reply SYN+ACK sent\n");
    } else if (flags & 0x10) { // ACK
        // 这里只做简单的 ACK 处理
        printf("tcp_input: received ACK\n");
        // 这里可以更新连接状态等
    }

    mbuffree(m);
}
```

#### 向用户态程序暴露接口

实现完关键的tcp逻辑后，我们需要建立相应的系统调用。

为了便于测试，此处建立一个特殊的系统调用用于一次性发送tcp报文

```c
//tcp实验系统调用
#define SYS_sendrawtcp  31
```

剩余注册并实现该系统调用的过程不再赘述

然后编写一个用户态程序用于测试：

```c
#include "kernel/types.h"
#include "kernel/net.h"
#include "user/user.h"

int main() {
    struct tcp pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.sport = htons(1234);
    pkt.dport = htons(80);
    pkt.seq = htonl(0);
    pkt.ack = htonl(0);
    pkt.off = (sizeof(struct tcp) / 4) << 4;
    pkt.flags = 0x02; // SYN
    pkt.window = htons(65535);

    sendrawtcp(&pkt, sizeof(pkt), (10<<24)|(0<<16)|(2<<8)|2, 1234, 80);
    exit(0);
}
```

使用wireshark进行抓包：

