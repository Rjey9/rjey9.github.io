---
draft: false
---
### 进程 Process

##### 进程的概念

程序是静态的，是存放在硬盘中的可执行文件，是数据与指令的集合，是一个副本

进程是动态的，是程序的一次执行过程，是一个实例

同一个程序可以建立多个不同的进程，就像docker中镜像与容器的概念

##### 进程的组成——PCB

当进程被创建时，操作系统会为该进程分配一个唯一的PID (Process ID)

操作系统要记录PID、进程所属用户ID(UID)，还要记录给进程分配的资源以及进程的运行情况等。所以需要**PCB (Process Control Block) 进程控制块**，该数据结构可以帮助操作系统维护进程的控制与调度

PCB中维护了以下信息：

- 进程描述信息：PID、UID
- 进程控制和管理信息：CPU、磁盘、网络流量使用、进程当前状态
- 资源分配清单：使用的文件、内存、IO设备
- 处理器相关信息：如PSW、PC等寄存器的值

以loOS为例，其PCB定义如下：

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

当进程创建时，操作系统会为其创建PCB。当进程结束时，会回收其PCB



