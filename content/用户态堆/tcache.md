---
title: tcache attack
date: 2025-3-7 14:00:00 +0800
categories:
  - Blog
  - pwn
tags:
  - pwn
description: 如果一个cache不够解决问题，那就再加一个cache
draft: false
---

## tcache相关结构体(libc 2.23版本)
tcache_perthread_struct：
```c
typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;
```
该结构体用于维护tcache bins
- counts数组存放每种大小的bin中当前存放的chunk数量
- entries数组存放64种bin的首地址
- 每个 thread 都会维护一个 tcache_perthread_struct

tcache_entry:
```c
typedef struct tcache_entry
{
  struct tcache_entry *next; 
} tcache_entry;
```
该结构体用于维护tcache bins中的chunk
- next直接指向下一个chunk的fd而非chunk header


与tcache相关的函数有两个：tcache_put()与tcache_get()，前者用于将chunk置入tcache bin，后者用于将chunk取出tcache bin
## tcache机制
- tcache bin与fast bin在某种程度上很相似：都是单链表、LIFO。但tcache bins可以存放从24 bytes - 1032 bytes大小的所有非large bin chunk，然而每种大小的bin最多存放7个chunk
- tcache_perthread_struct结构体本身是以堆的形式与其他堆放在一起的，大小为0x250。第一次malloc时，会先malloc一块内存用于存放tcache_perthread_struct
- tcache bin的优先级高于fast bin：即当释放一个chunk时，在放入fast bin之前，若tcache中有对应bin未满，则优先放入tcache bin中
- tcache有相当高的chunk存储优先级，体现如下：
  - 当对应大小的tcache bin为空，如果 fastbin/smallbin/unsorted bin 中有 size 符合的 chunk，会先把 fastbin/smallbin/unsorted bin 中的 chunk 放到 tcache 中，直到填满。之后再从 tcache 中取；因此 chunk 在 bin 中和 tcache 中的顺序会反过来
  - 当对应大小的tcache bin有chunk但未满，却从fastbin/smallbin中取chunk时，有：
    - 从fastbin中返回一个chunk，则单链表中剩下的堆块都会被放入对应的tcache bin中直到上限
    - small bin虽然双链表，但同上。需要注意的是，除了检测第一个堆块的fd指针，都缺失了__glibc_unlikely(bck -> fd != victim)的双向链表完整性检测。
- tcache中的chunk和fast bin一样，不会被合并(不取消inuse位)
-  calloc()越过tcache取chunk，通过calloc()分配的堆块会清零
- 与fastbin不同的是，当从tcache中取chunk时，并没有相关代码检验chunk是否符合fastbin大小

## tcache poisoning
如果能够对tacache bin中的chunk fd字段进行修改，使其指向任意地址，再通过malloc申请到该地址，由于缺乏对该地址的size检测，甚至不需要伪造fake chunk，就能够直接实现任意地址写。同时指向的地址就是user data地址而不用考虑偏移。

- glibc 2.29
  该版本添加了size检查，故需要在目标位置伪造size
- glibc 2.31
  glibc添加了对tcache的count检查，即当对应大小count小于0时，无法再从该类型tcache bin中malloc到chunk。这很好绕过，多free一个tcache chunk进入bin中即可(或者溢出/修改到count字段？)
- glibc 2.32
  会检查目标位置是否对齐；tcache的fd指针会被异或加密：
  ```python
  chunk->fd = target ^ (address >> 12);
  ```

## tcache double free
类似于fastbin double free因而没有任何难度。由于低版本不像fast bin那样还有对double free的直接检查，tcache_get()甚至连任何安全检查都没有，可以进行直接的两次连续free()
- glibc 2.27
  简单的double free成为历史。(2.27前期版本有，从ubuntu1.3开始加入key)
  
  tcache_chunk的bk处添加一个`key`字段，对于每一个进入tcache bin的chunk都会使其bk处的key字段等于一个值。当double free时会检测该字段是否等于key，如果等于则检测出为double free。绕过即将chunk的bk字段修改掉只要不等于key就好
  
  在glibc 2.27 - 2.33间，key的值为tcache_perthread_struct的地址，因而可以通过其leak堆地址

  在glibc 2.33以后，tcache的key变为随机数，无法再leak堆地址

## tcache house of spirit
与fast bin的house of spirit相同
- glibc 2.26 - 2.28
  此时的tcache还未引入size检查，因此比fastbin house of spirit更加强力直接，无需在目标地址伪造size
- glibc 2.29
  该版本引入size检查，需要如同fast bin一样伪造size

## tcache_stash_unlink_attack

- calloc会绕过tcache进行取chunk，取到chunk后会将chunk清空内容
- smallbin有特性：从smallbin中取chunk后，small bin中剩下的chunk会被挂入tcache
  
基于以上两点，可以进行以下操作：

malloc一个tcache chunk，将其释放进tcache bins，然后利用UAF或其他漏洞修改该chunk的bk为fake chunk addr，假设此时我们small bin中已经有其他chunk，我们进行一次calloc从small bin中取chunk，会导致tcache chunk全部进入small bin。在将该chunk插入small bin的过程中，实际上是从单链表变成了双链表，于是fake chunk被插入small bin；将victim -> bk -> fd = small bin，可以导致该位置写入一个极大值

## tcache_perthread_struct hijacking

一种思路。由于该结构体以堆0x250的形式在heap中，可以尝试劫持其内容，
- 控制counts：可以绕过tcache进行free chunks
- 控制entries：直接进行tcache poisoning




