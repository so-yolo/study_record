# pwn 题输出函数换行规则对比表

这个问题抓得很准，核心不是`recvuntil`函数带换行，而是**服务器端程序的输出函数**决定了数据末尾是否有换行，`recvuntil`只是被动接收这些数据。

在 pwn 题常见的 C 语言程序中，以下输出函数会在内容末尾自动添加换行符，直接影响你用`recvuntil`接收时的匹配目标。

### 1. `puts(const char *str)`：强制自动加换行

这是最常见的 “自动带换行” 函数，核心特点是**无论输入字符串是否包含**`\n`**，输出后都会额外追加一个换行符**。



* 示例：若服务器代码为`puts("flag{test}")`，实际输出到网络流的数据是`flag{test}\n`。

* 对应`recvuntil`用法：需匹配带换行的字符串，如`recvuntil(b"flag{test}\n")`。

### 2. `perror(const char *s)`：错误信息后自动加换行

该函数用于输出系统错误信息，格式为 “自定义提示 + 冒号 + 错误描述 + 换行符”，末尾换行由函数自动添加。



* 示例：`perror("open file failed")`，实际输出可能是`open file failed: No such file or directory\n`。

* 对应`recvuntil`用法：若要接收错误提示，需匹配到`\n`结尾，如`recvuntil(b"No such file or directory\n")`。

### 3. 注意：这些函数**不会**自动加换行

很多时候`recvuntil`接收不到换行，是因为服务器用了以下函数，需手动在格式串中加`\n`才会有换行。



* `printf(const char *format, ...)`：仅当格式串中包含`\n`时才会输出换行。

  示例：`printf("hello")`输出`hello`（无换行），`printf("hello\n")`才输出`hello\n`。

* `fputs(const char *str, FILE *stream)`：按字符串原样输出，不追加任何字符（包括换行）。

  示例：`fputs("hello", stdout)`输出`hello`（无换行），需写成`fputs("hello\n", stdout)`才会带换行。



***

为了方便你快速对照，要不要我帮你整理一份**pwn 题常见输出函数换行规则对比表**？表里会明确每个函数是否自动加换行、示例代码和对应的`recvuntil`匹配方式，直接用在做题里很方便。

> （注：文档部分内容可能由 AI 生成）