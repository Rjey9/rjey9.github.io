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

## 从wsl调用ida脚本

32位：

```shell
#!/bin/bash

# 检查是否提供了文件名作为参数
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <filename>"
    exit 1
fi

# 获取文件名
FILENAME=$1
REAL_PATH=$(realpath "$FILENAME")
# 检查文件是否存在
if [ ! -f "$FILENAME" ]; then
    echo "File not found: $FILENAME"
    exit 1
fi

# 将Linux文件路径转换为Windows文件路径
# 假设WSL的挂载点是/mnt/c，根据你的实际情况进行调整
WINDOWS_PATH="\\wsl.localhost"

# 检查ida32是否在PATH中，如果不在，需要指定完整路径
# 这里使用which命令查找ida32，如果没有安装which，可以注释掉下面两行，并直接使用ida32的 完整路径
IDA_PATH="C:\Users\33206\Desktop\PwnTools\IDA\ida.exe"
if [ -z "$IDA_PATH" ]; then
    echo "ida32 not found in PATH. Please specify the full path to ida32."
    exit 1
fi

# 启动ida32并传递文件路径
powershell.exe -Command "Start-Process -FilePath '$IDA_PATH' -ArgumentList '$REAL_PATH'"
```

64位：

```shell
#!/bin/bash

# 检查是否提供了文件名作为参数
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <filename>"
    exit 1
fi

# 获取文件名
FILENAME=$1
REAL_PATH=$(realpath "$FILENAME")
# 检查文件是否存在
if [ ! -f "$FILENAME" ]; then
    echo "File not found: $FILENAME"
    exit 1
fi

# 将Linux文件路径转换为Windows文件路径
# 假设WSL的挂载点是/mnt/c，根据你的实际情况进行调整
WINDOWS_PATH="\\wsl.localhost"

# 检查ida64是否在PATH中，如果不在，需要指定完整路径
# 这里使用which命令查找ida64，如果没有安装which，可以注释掉下面两行，并直接使用ida64的 完整路径
IDA_PATH="C:\Users\33206\Desktop\PwnTools\IDA\ida64.exe"
if [ -z "$IDA_PATH" ]; then
    echo "ida64 not found in PATH. Please specify the full path to ida64."
    exit 1
fi

# 启动ida64并传递文件路径
powershell.exe -Command "Start-Process -FilePath '$IDA_PATH' -ArgumentList '$REAL_PATH'"
```

## tmux配置：

```shell

set -g base-index         1     # 窗口编号从 1 开始计数
set -g display-panes-time 10000 # PREFIX-Q 显示编号的驻留时长，单位 ms
set -g mouse              on    # 开启鼠标
set -g pane-base-index    1     # 窗格编号从 1 开始计数
set -g renumber-windows   on    # 关掉某个窗口后，编号重排
set -g default-shell /bin/fish

bind -n M-h select-pane -L
bind -n M-l select-pane -R
bind -n M-j select-pane -U
bind -n M-k select-pane -D

bind -n M-1 select-window -t 1
bind -n M-2 select-window -t 2
bind -n M-3 select-window -t 3
bind -n M-4 select-window -t 4
bind -n M-5 select-window -t 5
bind -n M-6 select-window -t 6
bind -n M-7 select-window -t 7
bind -n M-8 select-window -t 8
bind -n M-9 select-window -t 9

bind -n M-n next-layout

bind h splitw -h -c '#{pane_current_path}'  # 水平分屏（左右分割）
bind j splitw -v -c '#{pane_current_path}'  # 垂直分屏（上下分割，向下）
bind k splitw -v -c '#{pane_current_path}'  # 垂直分屏（上下分割，向上）
bind l splitw -h -c '#{pane_current_path}'  # 水平分屏（左右分割）

#set -g @plugin 'erikw/tmux-powerline'
# default statusbar colors
#set -g status-bg black
#setw -g window-status-bell-style bg=black


set-option -g status-left "#(~/.config/tmux/tmux-powerline/powerline.sh left)"
set-option -g status-right "#(~/.config/tmux/tmux-powerline/powerline.sh right)"

set -g @plugin 'tmux-plugins/tpm'
set -g @plugin 'tmux-plugins/tmux-sensible'
run '~/.tmux/plugins/tpm/tpm'
```