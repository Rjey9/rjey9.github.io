---
draft: false
---

### 打开kernel调试选项

在`loos-lab-2025`目录下运行命令

```shell
make menuconfig
```

进入kernel编译菜单，Enable Debugging Output，然后保存退出

进入下一步

### GDB

不能使用原生GDB，也不能使用`gdb-multiarch`，其并不支持LoongArch

只能使用Loongsonlab官方提供的工具链中的gdb

运行如下命令：

```shell
git clone https://github.com/LoongsonLab/oscomp-toolchains-for-oskernel.git
cd oscomp-toolchains-for-oskernel/loongarch64-linux-gnu-gdb/bin
./loongarch64-linux-gnu-gdb <path/to/kernel>
```

其中，`<path/to/kernel>`在我这里是`~/loOS/loos-lab-2025/kernel`，即编译好的`ELF 64-bit LSB executable, LoongArch`文件

如果打开gdb后出现的提示信息中有如下信息：

```shell
This GDB was configured as "--host=x86_64-pc-linux-gnu --target=loongarch64-linux-gnu"

......

Reading symbols from /home/nokk/loOS/loos-lab-2025/kernel...
```

证明gdb目标架构正确且成功读取符号信息

此时GDB已经开始运行，进入下一步

### 此时，另一边...

此时打开另一个shell，进入`loos-lab-2025`目录，运行`make lorunqemugdb`，如果不出意外，会停止在如下位置：

```shell
~/l/loos-lab-2025 ❯❯❯ make lorunqemugdb                        
file /home/nokk/loOS/loos-lab-2025/toolchain/loongarch/rootfs.img.gz already exists.
file /home/nokk/loOS/loos-lab-2025/toolchain/loongarch/gcc-13.2.0-loongarch64-linux-gnu-nw.tgz already exists.
file /home/nokk/loOS/loos-lab-2025/toolchain/loongarch/qemu-2k1000-static.20240526.tar.xz already exists.
all file have downloaded!
make[2]: Nothing to be done for '__all'.
make[2]: Nothing to be done for '__all'.
make[2]: Nothing to be done for '__all'.
make[3]: Nothing to be done for '__all'.
make[3]: Nothing to be done for '__all'.
make[2]: Nothing to be done for '__all'.
make[3]: Nothing to be done for '__all'.
cp /home/nokk/loOS/loos-lab-2025/build_loongarch/bootdev.img /home/nokk/loOS/loos-lab-2025/toolchain/loongarch/qemu/2k1000/boot.img
cp -rfuT /home/nokk/loOS/loos-lab-2025/toolchain/loongarch/qemu /tmp/qemu
#  -e /home/nokk/loOS/loos-lab-2025/toolchain/loongarch/gcc-13.2.0-loongarch64-linux-gnu-nw/bin/loongarch64-linux-gnu-gdb -ex "target remote 0.0.0.0:3456" /home/nokk/loOS/loos-lab-2025/kernel 2>&1 1> /dev/null &
cd /home/nokk/loOS/loos-lab-2025/toolchain/loongarch/qemu; ./runqemu-debug
WARNING: Image format was not specified for './2k1000/u-boot-with-spl.bin' and probing guessed raw.
         Automatically detecting the format is dangerous for raw images, write operations on block 0 will be restricted.
         Specify the 'raw' format explicitly to remove the restrictions.
WARNING: Image format was not specified for './2k1000/boot.img' and probing guessed raw.
         Automatically detecting the format is dangerous for raw images, write operations on block 0 will be restricted.
         Specify the 'raw' format explicitly to remove the restrictions.
WARNING: Image format was not specified for './2k1000/rootfs.img' and probing guessed raw.
         Automatically detecting the format is dangerous for raw images, write operations on block 0 will be restricted.
         Specify the 'raw' format explicitly to remove the restrictions.
hda-duplex: hda_audio_init: cad 0
audio: Could not init `oss' audio driver
ram=0x5b6b62b90700
length=852992 must be 16777216 bytes,run command:
trucate -s 16777216 file
 to resize file
oobsize = 64




qemu-system-loongarch64: warning: nic pci-synopgmac.1 has no peer
qemu-system-loongarch64: warning: nic e1000e.0 has no peer
hda-duplex: hda_audio_reset
hda-duplex: hda_audio_reset
intel-hda: intel_hda_update_irq: level 0 [intx]
```

此时kernel已经运行，等待gdb连接上来（阅读lorunqemugdb脚本会知道qemu对gdb暴露在3456端口上）

我们回到刚刚的GDB shell中，运行如下命令：

```shell
target remote localhost:3456
```

此时能成功连接上。

到这一步，已经能够使用GDB对kernel进行调试

### 用惯pwndbg的我无法忍受原生GDB

旧版pwndbg不支持loongarch 然而新版pwndbg已经支持

进入你的用户目录`~`

```shell
git clone https://github.com/pwndbg/pwndbg.git
cd pwndbg
./setup.sh
```

另外，发现pwngdb中关于loongarch64的寄存器约定不符合实际，可以对其做出修改：

在pwndbg/lib/regs.py中找到如下代码：

```python
loongarch64 = RegisterSet(
    pc=Reg("pc"),
    stack=Reg("sp"),
    frame=Reg("fp"),
    retaddr=(Reg("ra"),),
    gpr=(
        Reg("a0"),
        Reg("a1"),
        Reg("a2"),
        Reg("a3"),
        Reg("a4"),
        Reg("a5"),
        Reg("a6"),
        Reg("a7"),
        Reg("t0"),
        Reg("t1"),
        Reg("t2"),
        Reg("t3"),
        Reg("t4"),
        Reg("t5"),
        Reg("t6"),
        Reg("t7"),
        Reg("t8"),
        Reg("s0"),
        Reg("s1"),
        Reg("s2"),
        Reg("s3"),
        Reg("s4"),
        Reg("s5"),
        Reg("s6"),
        Reg("s7"),
        Reg("s8"),
    ),
    args=(
        "a0",
        "a1",
        "a2",
        "a3",
        "a4",
        "a5",
        "a6",
        "a7",
    ),
    # r21 stores "percpu base address", referred to as "u0" in the kernel
    misc=("tp", "r21"),
)
```

将其替换为：

```python
loongarch64 = RegisterSet(
    pc=Reg("pc"),
    stack=Reg("sp"),
    frame=Reg("fp"),
    retaddr=(Reg("ra"),),
    gpr=(
        Reg("r0"),  # $zero
        Reg("r1"),  # $ra
        Reg("r2"),  # $tp
        Reg("r3"),  # $sp
        Reg("r4"),  # $a0
        Reg("r5"),  # $a1
        Reg("r6"),  # $a2
        Reg("r7"),  # $a3
        Reg("r8"),  # $a4
        Reg("r9"),  # $a5
        Reg("r10"), # $a6
        Reg("r11"), # $a7
        Reg("r12"), # $t0
        Reg("r13"), # $t1
        Reg("r14"), # $t2
        Reg("r15"), # $t3
        Reg("r16"), # $t4
        Reg("r17"), # $t5
        Reg("r18"), # $t6
        Reg("r19"), # $t7
        Reg("r20"), # $t8
        Reg("r21"), # $u0
        Reg("r22"), # $fp
        Reg("r23"), # $s0
        Reg("r24"), # $s1
        Reg("r25"), # $s2
        Reg("r26"), # $s3
        Reg("r27"), # $s4
        Reg("r28"), # $s5
        Reg("r29"), # $s6
        Reg("r30"), # $s7
        Reg("r31"), # $s8
    ),
    args=(
        "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
    ),
    # r21 stores "percpu base address", referred to as "u0" in the kernel
    misc=("tp", "u0"),
)
```