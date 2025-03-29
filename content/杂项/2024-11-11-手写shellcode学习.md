---
title: 手搓shellcode 个人笔记
date: 2024-11-11 21:00:00 +0800
categories: [Blog, pwn]
tags: [pwn]
draft: false
---
# 手搓shellcode 个人笔记
随着题目的难度加大，简单的通用shellcode愈发难以满足需求，面对各种各样的限制，我们需要学会手写shellcode以面对包括但不限于
1. shellcode长度限制
2. 字符限制
3. 工作状态限制
    ...等等 

想要快速进行手写shellcode，最好的办法就是在一段模板的基础上进行修改： 

```armasm
    mov rbx, 0x0068732f6e69622f
    push rbx
    mov rdi,rsp
    mov rsi,0
    mov rdx,0
    mov rax,59
    syscall
```
这是一段64位下的shellcode，期望执行execve("/bin/sh",0 ,0)<br>对其逐行解释：
1. `mov rbx, 0x0068732f6e69622f` 
   将command传入`rbx`寄存器，`0x0068732f6e69622f`是`/bin/sh`的小端序十六进制形式
2. `push rbx` 
    将`rbx`寄存器中的内容，即`/bin/sh`压入栈
3. `mov rdi,rsp` 
    将`rsp`中存储的地址传给`rdi`寄存器，此时`rdi`中存储了一个指针，该指针指向`/bin/sh`字符串
4. `mov rsi,0;mov rdx,0` 
   不用多说，将剩余两个参数置0 
5. `mov rax,59` 
   设置系统调用号为59 即execve的系统调用号
6. `syscall` 
    执行系统调用
## 长度限制 
在以上的基础上，加入题目对我们进行了长度限制，此时我们需要尽可能地缩短shellcode长度<br>
首先可以做的就是：
- 用`pop`、`push`代替`mov`<br>
  如用`push 0;pop rdi`来代替`mov rdi, 0`<br>为什么可以这么做呢？因为`push`、`pop`两种指令只占一个字节，而`mov`指令一般需要4个字节以上（这种设计应该是依据霍夫曼树不等长字符编码）<br>
- 用`xor`相同寄存器代替`mov xxx, 0`<br>
  学过逻辑代数的我们都知道，一个数自己对自己xor就相当于清零，并且这样做只需要2，3个字节
- 观察shellcode执行环境下的寄存器状态<br>
  这个很好理解，如果shellcode执行时`rsi`,`rdx`寄存器刚好为0，那么我们就可以在shellcode编写中省去置零的两步。<br>
- 曲线救国，先执行read，再写入更多的字节<br>
  构造函数`read(0,addr,len)`，此时往往需要观察寄存器状态，尽量利用有效数据以最短的字节达到我们的目的
## 限制字符shellcode
### ascii shellcode
题目会限制输入的字符必须是可见字符，即ascii码范围内的字符，这就需要对汇编指令所映射的机器码有了解，可以参考该网站：
[https://nets.ec/Ascii_shellcode](https://nets.ec/Ascii_shellcode) 
### 字母数字 shellcode
### 小写字母数字shellcode
## 00截断
