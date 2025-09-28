# ARM64 Mac 调试 x64 Pwn 程序

在 ARM64 架构的 Mac 本地调试 x64 架构的 Pwn 程序，核心是解决 **“ARM64 硬件无法直接运行 x64 程序”** 的矛盾，需通过 **架构转译工具（Rosetta 2）** 或 **x86\_64 容器环境** 配合调试器实现。以下是两种主流方案的详细步骤，包含工具安装、调试配置和实战示例：

### 方案一：本地转译（Rosetta 2 + x64 调试器）

利用苹果自带的 **Rosetta 2** 转译 x64 程序，搭配 x64 版本的调试器（如 GDB、LLDB），实现本地直接调试。适合快速验证小型 Pwn 程序。

#### 1. 前置条件：安装 Rosetta 2

Rosetta 2 是 ARM64 Mac 运行 x64 程序的核心转译工具，默认未安装需手动触发：



```
\# 终端执行以下命令，按提示安装 Rosetta 2

softwareupdate --install-rosetta --agree-to-license
```

验证安装：`/usr/libexec/rosetta/translate --version` 显示版本信息即成功。

#### 2. 安装 x64 版本的调试器（GDB/LLDB）

系统自带的 GDB/LLDB 是 ARM64 版本，无法调试 x64 程序，需安装 **x64 架构的调试器**，推荐通过 Homebrew 或预编译包安装。

##### （1）安装 x64 版 GDB



```
\# 1. 安装 Homebrew（若未安装）

/bin/bash -c "\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

\# 2. 安装 x64 版 GDB（通过 Homebrew 强制指定架构）

arch -x86\_64 brew install gdb
```

验证架构：`file /usr/local/bin/gdb` 输出含 `x86_64` 即正确。

##### （2）安装 x64 版 LLDB（可选，更轻量）

LLDB 对 x64 程序的兼容性更好，可通过 Xcode 命令行工具安装 x64 版本：



```
\# 安装 Xcode 命令行工具（含 x64 版 LLDB）

xcode-select --install

\# 验证：通过 Rosetta 启动 x64 LLDB

arch -x86\_64 lldb --version  # 输出含 "x86\_64" 即正确
```

#### 3. 调试 x64 Pwn 程序（实战示例）

假设你已编译好 x64 程序 `vuln_x64`（如之前通过 Docker 编译的缓冲区溢出程序），步骤如下：

##### （1）用 Rosetta 2 启动 x64 程序（后台运行，等待调试）



```
\# 用 Rosetta 转译启动程序，加 -g 选项允许调试（编译时需带 -g 生成调试信息）

arch -x86\_64 ./vuln\_x64 &  # 末尾 & 表示后台运行

\# 记录程序 PID（后续调试器需附加），例如输出 \[1] 12345，PID 为 12345
```

##### （2）用 x64 GDB 附加调试



```
\# 启动 x64 版 GDB，附加到目标 PID

arch -x86\_64 gdb -p 12345

\# GDB 调试常用命令

(gdb) break main  # 在 main 函数设断点

(gdb) c           # 继续运行到断点

(gdb) x/20xw \$rsp # 查看栈内存（x64 栈指针为 \$rsp）

(gdb) si          # 单步执行（进入函数）

(gdb) info reg    # 查看 x64 寄存器（如 rax、rbx）
```

##### （3）用 x64 LLDB 调试（更简洁）



```
\# 直接用 x64 LLDB 启动程序（无需手动后台运行）

arch -x86\_64 lldb ./vuln\_x64

\# LLDB 调试常用命令

(lldb) b main          # 设断点

(lldb) run             # 运行程序

(lldb) memory read \$rsp # 查看栈内存

(lldb) register read   # 查看 x64 寄存器

(lldb) ni              # 单步执行（跳过函数）
```

### 方案二：Docker 容器（x86\_64 环境）+ 远程调试

若程序依赖复杂的 x64 库（如旧版 glibc），或 Rosetta 转译不稳定，推荐用 **x86\_64 架构的 Docker 容器** 运行程序，通过 Mac 本地的调试器（如 IDA Pro、GDB）远程连接调试。稳定性优于本地转译，是 Pwn 调试的主流方案。

#### 1. 启动 x86\_64 容器并运行程序



```
\# 1. 拉取 x86\_64 版 Ubuntu 镜像（含基础调试环境）

docker pull --platform linux/amd64 ubuntu:22.04

\# 2. 启动容器（端口映射：容器 23946 端口 → Mac 23946 端口，用于远程调试）

docker run -it --rm \\

&#x20; \--platform linux/amd64 \  # 强制 x86\_64 架构

&#x20; -v \~/Desktop/pwn:/pwn \   # 挂载本地 Pwn 程序目录

&#x20; -p 23946:23946 \          # 映射调试端口（GDB/IDA 默认端口）

&#x20; \--name x64-pwn-container \\

&#x20; ubuntu:22.04 /bin/bash

\# 3. 在容器内安装调试依赖（若未安装）

apt update && apt install -y gdb netcat

\# 4. 启动程序并等待调试（用 GDB 远程调试模式）

cd /pwn

gdbserver 0.0.0.0:23946 ./vuln\_x64  # 监听 23946 端口，等待远程连接
```

此时容器内会显示：`Listening on port 23946`，表示程序已就绪，等待调试器连接。

#### 2. Mac 本地远程调试（两种工具可选）

##### （1）用 GDB 远程调试



```
\# 在 Mac 终端启动 x64 版 GDB（同方案一安装的版本）

arch -x86\_64 gdb

\# GDB 中连接容器内的程序

(gdb) target remote localhost:23946  # 连接本地 23946 端口（映射到容器）

(gdb) break main                     # 设断点

(gdb) c                              # 继续运行

(gdb) x/16xw \$rsp                    # 查看 x64 栈内存
```

##### （2）用 IDA Pro 远程调试（可视化更友好）



1. 打开 Mac 上的 IDA Pro（ARM64 版即可，支持跨架构调试）。

2. 加载 `vuln_x64` 程序，选择 **Debugger → Attach → Remote GDB Debugger**。

3. 在弹出的配置窗口中：

* **Hostname**：`localhost`（容器端口已映射到本地）

* **Port**：`23946`

* 点击 **OK** 连接，即可进入可视化调试界面（查看汇编、栈、寄存器）。

### 三、调试必备工具搭配（提升效率）



1. **pwntools（生成 payload + 交互）**

   Mac 本地安装 pwntools，可生成漏洞利用 payload，并与调试中的程序交互：



```
pip3 install pwntools

\# 示例：生成缓冲区溢出 payload，发送到调试中的程序

python3 -c "from pwn import \*; p = remote('localhost', 9999); p.send(b'A'\*72 + p64(0x401126)); p.interactive()"
```

若程序在容器内，可将 `localhost:9999` 替换为容器的端口映射（如 `localhost:10001`）。



1. **ROPgadget（查找 x64 ROP 链）**

   分析 x64 程序的 ROP  gadget，辅助构造利用链：



```
\# 安装 ROPgadget

pip3 install ropgadget

\# 查找程序中的 ROP gadget

ROPgadget --binary ./vuln\_x64 --ropchain
```

### 四、常见问题与解决方案



| 问题现象                                        | 原因                        | 解决方案                                                                                   |
| ------------------------------------------- | ------------------------- | -------------------------------------------------------------------------------------- |
| Rosetta 启动程序报错 “Bad CPU type in executable” | 程序不是 x64 架构，或 Rosetta 未安装 | 1. 用 `file ./vuln_x64` 确认是 “x86-64”；2. 重新安装 Rosetta：`softwareupdate --install-rosetta` |
| GDB 远程连接失败 “Connection refused”             | 容器端口未映射，或防火墙拦截            | 1. 确认启动容器时加了 `-p 23946:23946`；2. 关闭 Mac 防火墙（系统设置 → 网络 → 防火墙）                           |
| 调试时寄存器显示异常（如 \$rip 为 0）                     | 调试器与程序架构不匹配（用了 ARM64 调试器） | 确保用 `arch -x86_64 gdb` 启动 x64 版调试器                                                     |
| 程序依赖 “GLIBC\_2.27 not found”                | 容器内 glibc 版本与程序编译环境不一致    | 在容器内安装对应版本 glibc：`apt install libc6=2.27-3ubuntu1.6`                                   |

### 五、方案选择建议



* **快速调试小型程序**：选方案一（Rosetta 2 + x64 GDB），无需启动容器，步骤简单。

* **复杂程序 / 依赖旧库**：选方案二（Docker 容器 + 远程调试），环境隔离，稳定性高，适合 CTF 比赛或漏洞分析。

通过以上方案，你可以在 ARM64 Mac 本地高效调试 x64 架构的 Pwn 程序，覆盖从简单缓冲区溢出发挖到复杂 ROP 链构造的全流程。

> （注：文档部分内容可能由 AI 生成）