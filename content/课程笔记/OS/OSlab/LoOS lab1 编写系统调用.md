---
title: LoOS lab1 编写系统调用
draft: true
---

# Task 1

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

# Task 2

### 剩下的工作：RTC

##### 如何访问RTC

前面的工作只是适应一下`syscall`的实现，接下来要做的是实现`sys_clock_gettime`与`sys_gettimeofday`，而这两个均需要从`rtc.h`的`rtc_time`结构体中取信息

`rtc.c`与`rtc.h`中仅定义了结构体，声明了函数，并未对函数进行实现，这就是我们的工作

根据龙芯处理器用户手册可知，与`rtc`相关的各个寄存器均基于`RTC_REGISTER_BASE`进行寻址，而`RTC_REGISTER_BASE`又基于`BAR_BASE`加上偏移进行寻址。

![](课程笔记/OS/OSlab/images/Lab1/RTCreg.png)

这部分在`rtc.h`中已经实现：

```c
#define BAR_BASE               0x1FE2ULL  /* 0b1111111100010 */
#define RTC_REGISTER_BASE      ((BAR_BASE << 16) | (0x7 << 12) | (0x1 << 11))
```

但是在原lab的基础上，OS访问的并不是直接的物理地址0x1FE2700(+offset)，而是在基地址`0x9000000000000000`上访问虚拟地址

所以将`RTC_REGISTER_BASE`修改如下：

```c
#define RTC_REGISTER_BASE      (((BAR_BASE << 16) | (0x7 << 12) | (0x1 << 11))+0x9000000000000000)
```

基于`RTC_REGISTER_BASE`，我们可以利用偏移访问RTC模块寄存器，对其在`rtc.c`中进行宏定义如下：

```c
#define sys_toytrim (RTC_REGISTER_BASE + 0x20)
#define sys_toywrite0 (RTC_REGISTER_BASE + 0x24)
#define sys_toywrite1 (RTC_REGISTER_BASE + 0x28)
#define sys_toyread0 (RTC_REGISTER_BASE + 0x2C)
#define sys_toyread1 (RTC_REGISTER_BASE + 0x30)
#define sys_toymatch0 (RTC_REGISTER_BASE + 0x34)
#define sys_toymatch1 (RTC_REGISTER_BASE + 0x38)
#define sys_toymatch2 (RTC_REGISTER_BASE + 0x3C)
#define sys_rtcctrl (RTC_REGISTER_BASE + 0x40)
#define sys_rtctrim (RTC_REGISTER_BASE + 0x60)
#define sys_rtcwrite0 (RTC_REGISTER_BASE + 0x64)
#define sys_rtcread0 (RTC_REGISTER_BASE + 0x68)
#define sys_rtcmatch0 (RTC_REGISTER_BASE + 0x6C)
#define sys_rtcmatch1 (RTC_REGISTER_BASE + 0x70)
#define sys_rtcmatch2 (RTC_REGISTER_BASE + 0x74)
```

如果想要实现更上层的syscall，我们就首先需要实现与rtc相关的基本行为函数：`rtc_init`、`rtc_read_time`、`rtc_set_time`、`rtc_tm_to_sec`以及`rtc_sec_to_tm`

这些函数都涉及到对rtc相关寄存器的访问

根据龙芯手册，在使用RTC前必须要对`sys_rtcctrl`进行初始化：

根据下图，我们可以在`rtc_init`中进行对应置位

![](课程笔记/OS/OSlab/images/Lab1/sys_rtcctrl.png)


```c
/* 初始化RTC */
void rtc_init(void) {

	//输出调试信息
    printf("initializing RTC...\n");
    printf("sys_toytrim: %x\n", sys_toytrim);
    printf("sys_rtctrim: %x\n", sys_rtctrim);
    printf("sys_rtcctrl: %x\n", sys_rtcctrl);
    
     //set sys_toytrim reg
    uint32_t toytrim = *(volatile uint32_t *)sys_toytrim;
    toytrim = 0;
    *(volatile uint32_t *)sys_toytrim = toytrim;

    //set sys_rtctrim reg
    uint32_t rtctrim = *(volatile uint32_t *)sys_rtctrim;
    rtctrim = 0;
    *(volatile uint32_t *)sys_rtctrim = rtctrim;

    // set sys_rtcctrl reg
    uint32_t rtcctrl = *(volatile uint32_t *)sys_rtcctrl;
    rtcctrl |= (1 << 13); //第十三位 REN使能
    rtcctrl |= (1 << 11); //第十一位 TEN使能
    rtcctrl |= (1 << 8); //启用晶振
    *(volatile uint32_t *)sys_rtcctrl = rtcctrl;

    return;
}
```

接下来再在`kmain`函数中加入对`rtc_init`函数的调用，如此loOS才能在系统启动时对其进行初始化

```c
int kmain() {
    printf("kernel: start\n");
    w_csr_euen(1);
    // dump_dmw();
    dmw_init();
    // kinit();
    trap_init();
    tlb_init();
    vm_init();
    pmm_init();
    fs_init();
    proc_init();
    disk_init();
    user_init();
    rtc_init();
    intr_on();  
    printf("kernel: finish\n");
    scheduler();
    while (1);
    panic("should not reach here");
}
```

##### 如何完成考核

通过阅读`grade-lab1-rtc.py`可知，其测试原理是qemu启动loOS后运行`busybox date`命令，并从其中得到时间与现实时间进行比对。

通过查阅可知，Linux上的`date`命令其底层是调用了`sys_clock_gettime`，该接口对`timespec`结构体进行了设置，而后`date`从`timespec`中读取了秒数，转换为时间后显示。

有如下调用链：

![](课程笔记/OS/OSlab/images/Lab1/rtc_calls.png)

其中`date`已经由busybox实现，我们需要继续实现`sys_clock_gettime`与`rtc_read_time`与`rtc_tm_to_sec`

由于从rtc寄存器中读取时间，其主要方式是从各个二进制位上读取，因此写一个宏`EXTRACT_BITS`来完成按位访问：

```c
#define EXTRACT_BITS(var, start, end) \
((uint32_t)(((var) & (((1ULL << ((end) - (start) + 1)) - 1) << (start))) >> (start)))
```

对于`rtc_read_time`，有下图可以参考：

![](课程笔记/OS/OSlab/images/Lab1/sys_toyread0.png)

![](课程笔记/OS/OSlab/images/Lab1/sys_toyread1.png)

对应可以实现`rtc_read_time`函数如下：

```c
int rtc_read_time(struct rtc_time *tm) {
    if (tm == NULL) {
        return -1;
    }
    // printf("sys_toyread0 addr = 0x%08x\n", sys_toyread0);
    // printf("sys_toyread1 addr = 0x%08x\n", sys_toyread1);
    uint32_t TOYread0 = *(volatile uint32_t *)sys_toyread0;
    uint32_t TOYread1 = *(volatile uint32_t *)sys_toyread1;
    // printf("TOYread0 value = 0x%08x\n", TOYread0);
    // printf("TOYread1 value = 0x%08x\n", TOYread1);
    tm->tm_msec = EXTRACT_BITS(TOYread0, 0, 3) * 100;
    tm->tm_sec = EXTRACT_BITS(TOYread0, 4, 9);
    tm->tm_min = EXTRACT_BITS(TOYread0, 10, 15);
    tm->tm_hour = EXTRACT_BITS(TOYread0, 16, 20);
    tm->tm_mday = EXTRACT_BITS(TOYread0, 21, 25);
    tm->tm_mon = EXTRACT_BITS(TOYread0, 26, 31) - 1;
    // 直接读取完整年份
    tm->tm_year = TOYread1;
    tm->tm_wday = CALCULATE_WEEKDAY(tm);
    return 0;
}
```

再实现`rtc_tm_to_sec`函数如下

```c
/* 将RTC时间结构体转换为从1970年1月1日开始的秒数 */
uint64_t rtc_tm_to_sec(struct rtc_time *tm) {
    if (tm == NULL) {
        return -1;
    }
    // 每月的天数（非闰年）
    static const int days_in_month[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    uint64_t days = 0;
    // 计算从 1970 年到当前年份的天数
    for (int year = 1970; year < tm->tm_year + 1900; year++) {
        days += 365;
        if ((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)) {
            days += 1; // 闰年多一天
        }
    }
    // 计算当前年份中从 1 月到当前月份的天数
    for (int month = 0; month < tm->tm_mon; month++) {
        days += days_in_month[month];
        if (month == 1 && (((tm->tm_year + 1900) % 4 == 0 && (tm->tm_year + 1900) % 100 != 0) || ((tm->tm_year + 1900) % 400 == 0))) {
            days += 1; // 当前年份是闰年且当前月份是 2 月
        }
    }
    // 加上当前月份中的天数
    days += tm->tm_mday - 1;
    // 转换为秒数
    uint64_t seconds = days * 86400; // 每天 86400 秒
    seconds += tm->tm_hour * 3600;   // 每小时 3600 秒
    seconds += tm->tm_min * 60;      // 每分钟 60 秒
    seconds += tm->tm_sec;           // 秒
    return seconds;
}
```

`rtc_read_time`函数从rtc寄存器中读取时间并存储到`tm`结构体中，`rtc_tm_to_sec`函数从`tm`结构体中读取数据，转化为秒数返回给`sys_clock_gettime`函数，`sys_clock_gettime`依次对`timespec`结构体进行设置：

```c
uint64_t sys_clock_gettime(void) {
    uint64_t clock_id = argraw(0); //获取参数1
    uint64_t ts_addr = argraw(1); //获取参数2
    if (ts_addr == 0) {
        return -1; // timespec 指针无效
    }
    struct timespec *ts = (struct timespec *)ts_addr;

    switch (clock_id) {
        case CLOCK_REALTIME:
        case CLOCK_MONOTONIC:
        case CLOCK_PROCESS_CPUTIME_ID:
        case CLOCK_THREAD_CPUTIME_ID:
        case CLOCK_MONOTONIC_RAW:
        case CLOCK_REALTIME_COARSE:  //经过调试发现传入的clock_id为5，即CLOCK_REALTIME_COARSE
            //printf("jump here");
            //set rtc_time structure
            struct rtc_time *tm = (struct rtc_time *)malloc(sizeof(struct rtc_time));
            if (tm == NULL) {
                panic("rtc_init: malloc failed");
            } else {
                memset(tm, 0, sizeof(struct rtc_time));
            }
            rtc_read_time(tm);
            rtc_tm_to_sec(tm);
            uint64_t seconds = rtc_tm_to_sec(tm);
            ts->tv_sec = seconds;
            break;
        case CLOCK_MONOTONIC_COARSE:
        case CLOCK_BOOTTIME:
        default:
            return -1;
    }
    return 0;
}
```

后续运行测试脚本即可通过

##### 写在一切之后

为什么不在kmain里对rtc进行初始化也可以成功运行呢？