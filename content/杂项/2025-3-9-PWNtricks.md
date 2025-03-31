---
title: PWN tricks
date: 2025-3-9 00:00:00 +0800
categories: [Blog, pwn]
tags: [pwn]
description: 咦？这是什么？trick一下
---

## off by one 获取无法申请到的unsorted bin

通过off by one修改size可以进行overlap，此时进行free可以扩展堆大小，将其放入unsorted bin中

## double free泄露堆地址

如在glibc 2.26版本中，连续两次释放同一个tcache chunk，由于链中只有该chunk，导致其fd指向自己，此时show()可以泄露其fd，从而泄露堆地址

## patchelf脚本

免去繁琐的输入命令过程，自动化小帮手！

```shell
#!/bin/bash

# 显示帮助信息
usage() {
  echo "Usage: $0 <libc_version> <target_file>"
  echo "  <libc_version>: Version of the libc (e.g., 2.23)"
  echo "  <target_file>: Path to the target executable file (e.g., ./pwn)"
  exit 1
}

# 检查参数数量
if [ "$#" -ne 2 ]; then
  echo "Error: Invalid number of arguments."
  usage
fi

# 获取参数
LIBC_VERSION="$1"
TARGET_FILE="$2"
LIBC_ADDR=''
LD_ADDR=''

# 检查目标文件是否存在
if [ ! -f "$TARGET_FILE" ]; then
  echo "Error: Target file '$TARGET_FILE' does not exist."
  exit 1
fi

# 根据libc版本设置路径
case "$LIBC_VERSION" in
  2.23)
    LIBC_ADDR="/glibc-all-in-one/libs/2.23-0ubuntu3_amd64"
    LD_ADDR="/glibc-all-in-one/libs/2.23-0ubuntu3_amd64/ld-2.23.so"
    ;;
  *)
    echo "无对应glibc版本，请手动设置"
    exit 1
    ;;
esac

# 检查路径是否存在
if [ ! -d "$LIBC_ADDR" ]; then
  echo "Error: libc directory '$LIBC_ADDR' does not exist."
  exit 1
fi

if [ ! -f "$LD_ADDR" ]; then
  echo "Error: ld.so file '$LD_ADDR' does not exist."
  exit 1
fi

# 使用patchelf设置解释器和RPATH
patchelf --set-interpreter "$LD_ADDR" --set-rpath "$LIBC_ADDR" "$TARGET_FILE"

echo "已进行patchelf："
echo "ld: '$LD_ADDR'"
echo "rpath: '$LIBC_ADDR'"
echo "file: '$TARGET_FILE'"
```

将其写好后使用命令`sudo ln -s ~/my_scripts/patchpwn.sh /usr/bin/patchpwn`链接到环境中

## SROP

众所周知，当进程被挂起，由用户态切换到内核态时，内核会为进程保存上下文，该过程：

1. 将所有寄存器压入栈中，压入signal信息，压入sigreturn地址，此时栈呈现如下形式：
	![](杂项/images/PWNtricks/signal-stack.png)
2. 当kernal处理完系统调用后，会为进程回复上下文，即当kernal处理完系统调用后，会执行sigreturn代码，开始回复上下文，将ucontext回复到对应的位置
3. 我们称ucontext + siginfo为`signal frame`。signal frame会因为架构的不同而有所区别。
- x86
```c
struct sigcontext 
{ 
	unsigned short gs, __gsh; 
	unsigned short fs, __fsh; 
	unsigned short es, __esh; 
	unsigned short ds, __dsh;
	unsigned long edi; 
	unsigned long esi; 
	unsigned long ebp; 
	unsigned long esp;
	unsigned long ebx;
	unsigned long edx; 
	unsigned long ecx; 
	unsigned long eax; 
	unsigned long trapno; 
	unsigned long err; 
	unsigned long eip; 
	unsigned short cs, __csh; 
	unsigned long eflags; 
	unsigned long esp_at_signal; 
	unsigned short ss, __ssh; 
	struct _fpstate * fpstate; 
	unsigned long oldmask; 
	unsigned long cr2; 
};
```
- x64
```c
struct sigcontext 
{ 
	__uint64_t r8; 
	__uint64_t r9;
	__uint64_t r10; 
	__uint64_t r11;
	__uint64_t r12;
	__uint64_t r13; 
	__uint64_t r14; 
	__uint64_t r15; 
	__uint64_t rdi; 
	__uint64_t rsi; 
	__uint64_t rbp;
	__uint64_t rbx; 
	__uint64_t rdx;
	__uint64_t rax; 
	__uint64_t rcx; 
	__uint64_t rsp; 
	__uint64_t rip; 
	__uint64_t eflags; 
	unsigned short cs; 
	unsigned short gs; 
	unsigned short fs; 
	unsigned short __pad0; 
	__uint64_t err; 
	__uint64_t trapno; 
	__uint64_t oldmask; 
	__uint64_t cr2; 
	__extension__ union 
	{ 
		struct _fpstate * fpstate; 
		__uint64_t __fpstate_word;
	}; 
	__uint64_t __reserved1 [8]; 
};
```

值得注意的是，在该过程中，signal frame被保存在用户空间中，用户是可读写的。kernal也不关心signal frame的位置，所以当执行sigreturn时，signal frame可以被我们伪造

通过如下布局，可以实现连续SROP

![](杂项/images/PWNtricks/srop-example.png)

需要满足：

1. 可以控制程序执行流
2. 存在相应的gadget
3. 可以控制相当大的空间（存储fake frame）
