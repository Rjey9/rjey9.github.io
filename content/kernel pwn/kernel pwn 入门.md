---
draft: true
date: 2025-7
---
### 初步认识kernel pwn

kernel pwn的核心目标：提权。即从普通用户升级为root

kernel pwn的ctf题型按照**攻击面**进行分类可以分为：

- 设备驱动漏洞
- 文件系统漏洞
- eBPF子系统漏洞
- 内核调试接口/trace机制漏洞
- 系统调用逻辑漏洞
- 对内核本身进行漏洞利用：kernel本身、.ko模块
- 网络协议栈漏洞
- 虚拟化设备漏洞

而按照**漏洞类型**又可划分为：

- 提权
- 内核任意代码执行
- 逃逸

### kernel pwn 环境准备

##### 1.qemu

在CTF题中，一般kernel pwn会给出一个.sh文件，这个脚本实际上就是qemu命令的集合，会起qemu运行内核，一般是下面这样:

```shell
#!/bin/sh  
  
qemu-system-x86_64 \  
    -m 256M \			  # 参数设置RAM大小为64M  
    -kernel bzImage \     # 使用当前目录的bzImage作为内核镜像  
    -initrd rootfs.cpio \ # 指定使用rootfs.cpio作为初始RAM磁盘。可以使用cpio 命令提取这个cpio文件，提取出里面的需要的文件，比如init脚本和babydriver.ko的驱动文件。提取操作的命令放在下面的操作步骤中  
    -monitor /dev/null \  # 将监视器重定向到字符设备/dev/null  
    -append "root=/dev/ram console=ttyS0 loglevel=8 ttyS0,115200 kaslr" \  
    -cpu kvm64,+smep,+smap \  
    -netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \  
    -nographic \ 		  # 参数禁用图形输出并将串行I/O重定向到控制台  
    -no-reboot \		  # 发生重启时不要自动重启虚拟机  
    -no-shutdown 		  # 在虚拟机发出关闭信号（例如通过操作系统的关机命令）时不要自动关闭虚拟机。
```
##### 2. busybox

用来模拟一个精简而可调试的最小文件系统

### 第一道kernel pwn



