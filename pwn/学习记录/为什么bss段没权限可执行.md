### 面向返回编程不需要执行权限

- 对于 ROP 链，这个面向返回编程只需要的是地址，而不是 ret2shellcode 那样要先把 shellcode 写入可写可执行的段中，然后再 ret 到 shellcode，对于rop链我们只需要填写程序中存在的地址就行，这个时候我们将rop链写到bss段的时候我们不需要bss段存在可执行权限。对于写到bss段的shellcode，我们需要bss存在可执行权限，这是因为shellcode不是程序本就存在的代码，所以我们要运行它就需要在运行的地方存在可执行权限。

[关于 PWN 中的疑问 | iyheart 的博客](https://iyheart.github.io/2024/06/18/CTFblog/PWN%E7%B3%BB%E5%88%97blog/%E5%85%B3%E4%BA%8EPWN%E4%B8%AD%E7%9A%84%E7%96%91%E9%97%AE/index.html)


