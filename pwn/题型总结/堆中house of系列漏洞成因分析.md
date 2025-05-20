#### house of spirit
存在uaf漏洞，实现任意地址写

#### house of einherjar
存在poision null byte漏洞，实现\x00字节覆盖size字段，实现overlapping_chunk

#### house of roman
这个利用方式目前在2.23到2.29之间是可以利用的，而且对于漏洞点要求不高，主要是uaf和overflow（有一个uaf即可），在可以创建任意大小的堆块的情况下，不泄露出堆地址的情况下面，通过爆破（12bit也就是4096分之一），来getshell

说是一种house of，但是其实本质上没有涉及什么新的东西，只是一种fastbin和unsortedbin的结合利用而已，攻击大致分为三个阶段:

1. 通过低位地址改写使 fastbin chunk 的 fd 指针指向 __malloc_hook.
2. 通过 unsortedbin attack 把 main_arena 写到 malloc_hook 上.
3. 通过低位地址修改 __malloc_hook 为 one_gadget.

#### house of botcake
利用unsortedbin实现tcache的double free.

#### house of force
利用溢出实现top chunk的size位的覆盖，实现top chunk的大小的分配控制。

#### house of gods
后面再分析

#### house of lore
利用small bin的chunk的bk指针，使其指向构造好的假的chunk0，然后实现任意地址写


#### house of rabbit
利用fastbin的fd构造fakechunk，然后利用malloc_consolidate合并的效果实现fake进入largebin(我不知道为什么进入largebin)，然后将fake的size的大小改成非常大的，最后再malloc，就可以实现任意地址写了。

#### house of orange 
当申请的chunk的大小大于top chunk的时候就会将top chunk的空间放入unsortedbin的管理中，然后就是可以泄露libc，后续搭配unsortedbin attack或fsop进行攻击


#### house of pig
通过 libc-2.31 下的 largebin attack 以及 FILE 结构利用，来配合 libc-2.31 下的 tcache stashing unlink attack 进行组合利用的方法

- 运用场景：
    - 主要适用于程序中仅有 calloc 函数来申请 chunk，而没有调用 malloc 函数的情况
- 核心技术点：
    - 利用了 glibc 中 `IO_str_overflow` 函数内会连续调用 malloc，memcpy，free 函数的特点，并且这三个函数的参数都可以由 FILE 结构内的数据来控制


#### house of mind
有点复杂回来看

#### house of storm

