---
title: fast bin attack
date: 2025-3-7 15:00:00 +0800
categories:
  - Blog
  - pwn
tags:
  - pwn
description: faster faster faster!
draft: true
---

## fastbin double free

注意点：
1. fast bin对double free有检查，即检查fast bin指向的chunk与victim是否相同。所以不能连续两次释放同一个chunk。可以通过中间多free另一个chunk来绕过
2. fast bin会检查目标地址 + 8(即fake chunk的size位)是否符合fast bin大小

该漏洞可配合tcache stash机制绕过tcache double free针对key指针的检查

## house of spirit

漏洞成因：堆溢出写

![](用户态堆/images/fastbinattack/house_of_spirit1.png)

利用条件：
- 可以控制free的参数为fake chunk data address
- 可以如图进行fake chunk构造
- chunk位置需对齐，杜绝了我们使用“自然生成”的0x7f等进行利用，因为这种数据往往位置不对齐

利用效果：造成某特殊地址可任意写

- 可以释放栈中的fake chunk，劫持ret
- 释放堆中的fake chunk，劫持控制模块实现WAA

虽然是fast bin attack，但该思路对libc 2.26以上版本的tcache仍然适用，甚至没有对next chunk size的检查

libc-2.27之后多了一个检查，需要覆盖fake next chunk的prev_size不为0

## 总结
总而言之，我们可以利用fast bin单链表的特性，劫持其fd指针从而实现控制许多区域。但是需要注意的是，1. 这些区域的地址要可leak；2. 这些区域都需要进行size的check，这个size是人为覆盖还是自然形成的无所谓。

