---
title: Linux-Tricks
date: 2025-3-20 00:00:00 +0800
categories: [Blog, pwn]
tags: [pwn]
description: 工欲善其事，必先利其器。
---

我的设想：当打开WSL时，tmux会自动创建好两个Window，其中一个window打开blog的markdown编辑界面，便于我进行学习的记录和查阅；另一个window自动来到pwn环境中，我能够使用vim + tmux方便地编写、运行exp并与gdb良好地融合

## Tmux

## GDB

## Win-terminal
- 光标移动：
  - 向前：`c + F` / `->`
  - 向后：`c + B` / `<-`
  - 移动到行首： `c + A`
  - 移动到行尾： `c + E`
  - 按单词移动：`c + ->/<-`
- 其他有关光标的操作：
  - 清楚当前光标位置到行尾的内容： `c + K`
  - 清楚当前光标位置到行首的内容： `c + U`
  - 清楚当前光标位置字母： `c + D`
## Vim

