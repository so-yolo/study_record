house of spirit
存在uaf漏洞，实现任意地址写

house of einherjar
存在poision null byte漏洞，实现\x00字节覆盖size字段，实现overlapping_chunk

house of roman
这个利用方式目前在2.23到2.29之间是可以利用的，而且对于漏洞点要求不高，主要是uaf和overflow（有一个uaf即可），在可以创建任意大小的堆块的情况下，不泄露出堆地址的情况下面，通过爆破（12bit也就是4096分之一），来getshell

说是一种house of，但是其实本质上没有涉及什么新的东西，只是一种fastbin和unsortedbin的结合利用而已，攻击大致分为三个阶段:

1. 通过低位地址改写使 fastbin chunk 的 fd 指针指向 __malloc_hook.
2. 通过 unsortedbin attack 把 main_arena 写到 malloc_hook 上.
3. 通过低位地址修改 __malloc_hook 为 one_gadget.

house of botcake
利用unsortedbin实现tcache的double free.

house of force
利用溢出实现top chunk的size位的覆盖，实现top chunk的大小的分配控制。

house of gods
后面再分析

house of 



