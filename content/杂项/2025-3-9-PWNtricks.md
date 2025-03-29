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

## 带符号编译glibc，实现gdb调试glibc源代码

1. 下载对应glibc版本源码并解压，进入该目录
2. 创建两个目录：`mkdir glibc-2.xx_out glibc-2.xx_build`
3. 进入`glibc-2.xx_build`，