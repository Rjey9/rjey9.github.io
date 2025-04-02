---
title: LoOS lab1 编写系统调用
draft: false
---

### 当我们在LoOS里进行系统调用，实际上发生了什么？

###### 1. 用户态程序发起系统调用

如同Linux有glibc，LoOS也有自己的libc，即lolibc

在lolibc/unistd.h中有如下代码：

```c
#ifndef __UNISTD_H__
#define __UNISTD_H__

#include <stdint.h>
#include <syscall.h>

#define SYSCALL_CLOBBERLIST \
	"$t0", "$t1", "$t2", "$t3", \
	"$t4", "$t5", "$t6", "$t7", "$t8", "memory"

static inline uint64_t _syscall0(uint64_t NUMBER) {
    register uint64_t a0 __asm__("$a0");
	register uint64_t a7 __asm__("$a7") = NUMBER;

	__asm__ __volatile__ (
		"syscall 0"
		: "+&r"(a0)
		: "r"(a7)
		: SYSCALL_CLOBBERLIST);
	return a0;
}

static inline uint64_t _syscall3(uint64_t n, uint64_t a, uint64_t b, uint64_t c) {
	register uint64_t a0 __asm__("$a0") = a;
	register uint64_t a1 __asm__("$a1") = b;
	register uint64_t a2 __asm__("$a2") = c;
	register uint64_t a7 __asm__("$a7") = n;

	__asm__ __volatile__ (
		"syscall 0"
		: "+&r"(a0)
        : "r"(a7), "r"(a1), "r"(a2)
		: SYSCALL_CLOBBERLIST);
	return a0;
}

#define exit(ret) _syscall3(SYS_exit, ret, 0, 0)
#define openat(dirfd, pathname, flags) _syscall3(SYS_openat, dirfd, pathname, flags)
#define close(fd) _syscall3(SYS_close, fd, 0, 0)
#define read(fd, buf, count) _syscall3(SYS_read, fd, buf, count)
#define write(fd, buf, count) _syscall3(SYS_write, fd, buf, count)
#define lseek(fd, offset, whence) _syscall3(SYS_lseek, fd, offset, whence)
#define fstat(pathname, buf) _syscall3(SYS_fstat, pathname, buf, 0)
#define fcntl(fd, cmd, arg) _syscall3(SYS_fcntl, fd, cmd, arg)
#define getdents64(fd, dirp, count) _syscall3(SYS_getdents64, fd, dirp, count)

#endif

```

当进行系统调用时，首先会调用函数`_syscall3`，其主要作用是将系统调用号和函数参数压入对应的寄存器`a7` ，`a0`，`a1`，`a2`中（感觉只传三个参数会不会不太够用）

所有的用户态程序进行系统调用时，其底层最终都会执行该函数，被转化为汇编语言：

```c
	__asm__ __volatile__ (
		"syscall 0"
		: "+&r"(a0)
        : "r"(a7), "r"(a1), "r"(a2)
		: SYSCALL_CLOBBERLIST);
```

##### 2. 执行syscall 0，进入trap

在执行syscall 0之后，cpu会自动跳转到trap

在`core/trap_entry.s`中定义了trap行为：

```asm
#
# interrupts and exceptions while in privilege0
# push all registers, call trap_handler(), restore, return.
# 将上下文寄存器压入栈中，调用trap_handler()
.section trapentry
.globl trap_entry
.globl trap_exit
.globl trap_handler
.globl cur_sp
.align 4
trap_entry:
    # make room to save registers.
    # 保存进程寄存器值到trapFrame中，下面的行为实际上就是按照trapFrame结构体设置
    addi.d $sp, $sp, -320

    # save the registers.
    st.d $ra, $sp, 0
    st.d $tp, $sp, 8
	...
    st.d $s7, $sp, 232
    st.d $s8, $sp, 240

    csrrd $t0, 0x1      # prmd
    st.d $t0, $sp, 248
    csrrd $t0, 0x6      # era
    st.d $t0, $sp, 256

    # store real sp
    addi.d $a0, $sp, 320
    st.d $a0, $sp, 16

    # store sp to find trapframe 方便找到trapFrame
    la $a0, cur_sp
    st.d $sp, $a0, 0

	# call the C trap handler in trap.c 跳转到trap_handler
    bl trap_handler 
```

##### trap_handler判断trap类型，执行相应逻辑

在`core/trap.c`中定义了函数`trap_handler`

```c
void trap_handler() {
    // printf("trap triggered\n");
    uint32_t estat = r_csr_estat();
    uint32_t ecfg = r_csr_ecfg();
    uint64_t era = r_trap_era();
    uint64_t badv = r_csr_badv();
	...
        uint8_t ecode = (estat & CSR_ESTAT_ECODE) >> 16;
        uint16_t esubcode = (estat & CSR_ESTAT_ESUBCODE) >> 22;
        if (ecode == E_SYS) {
            // system call
            // intr_on();
            syscall_handler();
    ...
}
```

其会检查状态寄存器中的异常码，判断当前是要进行系统调用还是发生了其它类型的异常，如果是系统调用，就调用`syscall_handler`函数
##### syscall_handler函数

其被定义在`core/syscall.c`中，代码如下：

```c
void syscall_handler() {
    struct trapframe *trapframe = get_trapframe(); //获取当前进程的trapframe
    int num = trapframe->a7; //获取系统调用号
    uint64_t ret = -1;
    uint64_t (*syscall)() = NULL;
    if ((num >= sizeof(syscalls) / sizeof(syscalls[0])) || ((syscall = syscalls[num]) == NULL)) {
        printf("syscall id: %d\n", num);
        printf("id: %d, arg1: %x, arg2: %x, arg3: %x\n", num, argraw(0), argraw(1), argraw(2));
        // panic("syscall not implemented");
        printf("syscall not implemented\n");
        syscall = syscalls[SYS_exit_group];
    }
    ret = syscall();
    trapframe->a0 = ret;
}
```

在`syscall.c`中，不止有`syscall_handler`函数，还创建了`syscalls`数组

```c
static uint64_t (*syscalls[])(void) = {
    [SYS_openat]    sys_openat,
    [SYS_close]     sys_close,
    [SYS_read]      sys_read,
    [SYS_write]     sys_write,
    [SYS_lseek]     sys_lseek,
    [SYS_exit]      sys_exit,
    [SYS_fstat]     sys_return_wrong,
    ...
    [SYS_sendfile]          sys_sendfile,
```

可以把它看做一个表，作用是帮助`syscall_handler`调用对应的关键函数逻辑，如果还未实现对应的系统调用，则调用`sys_return_zero`。同时，由于在`include/syscall.h`中定义了系统调用号的相关宏，完成了根据系统调用号调用对应的函数
### 编写系统调用

##### 系统调用号表：

LoOS的系统调用号表位于`include/syscall.h`中，其表现形式如下：

```c
#ifndef __SYSCALL_H__
#define __SYSCALL_H__

#define SYS_io_setup 0
#define SYS_io_destroy 1
#define SYS_io_submit 2
#define SYS_io_cancel 3
#define SYS_io_getevents 4
#define SYS_setxattr 5
#define SYS_lsetxattr 6
#define SYS_fsetxattr 7
#define SYS_getxattr 8
#define SYS_lgetxattr 9
#define SYS_fgetxattr 10
#define SYS_listxattr 11
#define SYS_llistxattr 12
...
```

根据lab1要求，我们需要在`core/syscall.c`中实现系统调用`sys_getppid`

那么首先在`syscall.h`函数调用表中加上我们的函数调用

```c
#define SYS_getppid 173
```

已经很贴心地为我们定义好了 那没事了

然后进入到`core/syscall.c`中开始实现`sys_getppid`。该系统调用的功能应当是传入进程的pid，返回其父进程的pid，实现其功能代码如下：

```c
uint64_t sys_getppid(pid_t pid) {
    struct task_struct *p = proc_find(pid);
    if (p == NULL) {
        return -1; //找不到对应的进程
    }
    if (p->parent == NULL) {
        return -1; //找不到对应的父进程
    }
    return p->parent->pid; //获取父进程pid 
}
```

`proc_find`是定义在`core/proc.c`中的函数，可以返回进程pid对应的进程结构体，其结构体被定义在`asm/proc.h`中：

```c
struct task_struct {
    int pid; // 进程编号
    struct task_struct *parent; //父进程
    struct list_head children;  //子进程链表
    // struct list_head sibling;  //兄弟进程链表
    enum proc_state state; // 进程状态
    enum alloc_state allocs; // 进程分配状态
    struct context *context; // 
    struct trapframe *trapframe;
    struct fdtable * fdtable; // 文件描述符表
    uint64_t bss; // bss 段长度
    char name[32]; // 进程名
    char cwd[256]; // 进程目录
    pagetable_t pgtbl; // 进程页表
    void *mapping_list; // 进程映射列表
    void (*callback)(int); // 进程 signal 回调函数
    uint64_t timer_call_time; // SIGALRM 定时器
    struct list_head tasks;
	int exit_code; 				// the exit code of this process
};
```

拿到结构体后访问就完事儿了

但是还没完，还需要在`syscalls`数组中建立正确的链接：

```c
[SYS_getppid]           sys_getppid,
```

### 我们的第一个用户态程序

是，我们已经实现了系统调用，但是离真正能用还有一段距离。接下来，我们需要编写对应的用户态程序来调用刚刚编写好的系统调用

> 在 scripts/gradelib/ 目录编写汇编代码 sys_test.s 实现从用户态调用该系统调用。

根据Hint，来到`gradelib`目录下，可以找到一个测试文件grade-lab1-sys.py：

```python
#!/usr/bin/env python

import re
import os
import sys
from gradelib import *

# 创建Runner实例，将输出保存到sys.out文件
r = Runner(save("sys.out"))

@test(10, "getppid")
def test_getppid():
    # 运行QEMU并执行测试程序
    r.run_qemu(shell_script([
        '/bin/sys_test',
        'echo "getppid return: $?"',
        'exit'
    ]))
    
    # 检查输出中是否包含返回值
    match = re.search(r'getppid return: (\d+)', r.qemu.output)
    print(r.qemu.output, match)
    if match:
        ppid = int(match.group(1))
        if ppid == 1:
            print(f"\n获取的父进程ID为: {ppid}")
            print("测试通过：getppid系统调用成功实现！")
        else:
            print("测试失败：getppid系统调用返回了无效的父进程ID")
            raise AssertionError("getppid系统调用返回了无效的父进程ID")
    else:
        print("\n测试失败：无法获取getppid系统调用的返回值")
        raise AssertionError("无法获取getppid系统调用的返回值")

run_tests() 
```

注意到不需要提供pid作为参数，于是修改系统调用`sys_getppid`如下：

```c
uint64_t sys_getppid(void) {
    struct task_struct *p = my_proc();
    if (p == NULL) {
        return -1; //找不到对应的进程
    }
    if (p->parent == NULL) {
        return -1; //找不到对应的父进程
    }
    return p->parent->pid; //获取父进程pid 
}
```

编写`sys_test.s`如下：

```asm
.text
.global main
main:
    li.d $a7, 173           
    syscall 0         
      
```

注意末尾多一个换行符`\n`

使用loOS提供的编译工具进行编译，然后挂载运行即可

### 剩下的工作

##### 机器的心脏：RTC

##### 


``


