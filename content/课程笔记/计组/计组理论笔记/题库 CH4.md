
General-purpose architectures are divided into the following three groups:
- memory-memory, register-memory, and load-store.

_________ is the process whereby devices connected to a bus autonomously determine which of the devices shall have control over the bus:
- distributed arbitration using self-selection

The register that holds the address of the data to be transferred is called the __
- memory address register

If the opcode field for an instruction has n bits, that means there are _______ potential distinct operations.
- 2^n

A "subtract" statement is an example of a(n) _ instruction.
- arithmetic

What is the maximum value of the cycle counter when the following sequence of microoperations is executed?  
```
MAR ← X, MBR ← AC
M[MAR] ← MBR
```
- 1

Suppose a system has a byte-addressable memory size of 256MB. How many bits are required for each address?
- 28

Which MARIE instruction is being carried out by the RTN that follows?  
```
MAR ← X  
MBR ← M[MAR]  
MAR ← MBR  
MBR ← ACM  
[MAR] ← MBR
```
- StoreI X

Which MARIE instruction is being carried out by the RTN statement that follows?  
PC ← X
- Jump X

A computer bus consists of data lines, __________, control lines, and power lines.
- address lines

Accumulator architectures store one operand on the stack and the other in the accumulator.
- False

If a system's instruction set consists of a 5-bit opcode, what is the maximum number of output signal lines required for the control unit?
- 32

Which of the following is placed into the symbol table during the first pass?
- labels

Suppose a system has a byte-addressable memory size of 4GB. How many bits are required for each address?
- 32

Consider the postfix expression: A-B+C**(D**E-F)/(G+H*K). The equivalent postfix (reverse Polish notation) expression is:
- AB-CDE**F-**+GHK*+/.

If, after fetching a value from memory, we discover that the system has returned only half of the bits that we expected; it is likely that we have a problem with:
如果在从内存中获取一个值之后，我们发现系统只返回了我们预期一半的位数，那么很可能是存在
- byte alignment. 字节对齐问题

General-purpose register architectures are the most widely accepted models for computers today.
通用寄存器架构是当今计算机最广泛接受的模型
- True

Fixed-length instructions always have the same number of operands
定长指令总是具有相同数量的操作数
- False

Instruction sets are differentiated by which feature?
指令集通过以下哪个特征进行区分？
- Operand storage  Number of operands  Operand location  Operations

The best architecture for evaluating postfix notation is the stack-based architecture
评估后缀表示法的最佳架构是基于堆栈的架构
- True

Variable-length instructions are easier to decode than fixed-length instructions.
可变长指令比定长指令更容易解码。
- False

A fixed-length instruction must have fixed-length opcodes.
定长指令必须具有定长的操作码
- False

The ________ of a machine specifies the instructions that the computer can perform and the format for each instruction.
机器的____指定了计算机可以执行的指令以及每条指令的格式。
- instruction set architecture

The _______ connects the CPU to memory.
- system bus

Suppose that a system uses 16-bit memory words and its memory is built from 32 1M × 8 RAM chips. How many address bits are required to uniquely identify each memory word?
- 24

Suppose a computer's control unit consists of a 4-bit counter and a 4 × 16 decoder. What is the maximum number of clock cycles that can be consumed by any instruction?
假设一台计算机的控制单元由一个4位计数器和一个4×16的解码器组成。任何指令最多可以消耗的时钟周期数是多少？
- 16

Consider the infix expression: 16/(5+3). The equivalent postfix (reverse Polish notation) expression is:
- 16 5 3 + /

Clock skew is a problem for:
时钟偏斜是以下哪种总线的问题
- synchronous buses.同步总线

A Very Long Instruction Word (VLIW) is an architectural characteristic in which each instruction can specify multiple scalar operations.
超长指令字（VLIW）是一种体系结构特性，其中每条指令可以指定多个标量操作
- True

Memory organization has no effect on instruction format
存储器组织对指令格式没有影响
- False

The three basic ISA architectures for internal storage in the CPU are:
- stack, accumulator, and general-purpose registers.

Suppose we have a 4096 byte byte-addressable memory that is 64-way high-order interleaved, what is the size of the memory address module offset field?
- 10 bits

In order to pass parameters to subprograms, a(n) ___ must be implemented to support the ISA.
为了向子程序传递参数，必须实现一个（n）___ 来支持ISA
- stack

Big endian computers store a two-byte integer with the least significant byte at the lower address.
大端模式计算机将双字节整数的最低有效字节存储在较低的地址
- False

A stack-organized computer uses ___ addressing.
堆栈式计算机使用___寻址
- zero-address

A "jump" statement is an example of a(n) ____________ instruction.
- transfer of control  控制传输

Assembly language:
- uses alphabetic (mnemonic) codes in place of binary strings. 使用字母（助记符）代码代替二进制字符串。

