
#### libcsearcher

![[Pasted image 20240923213307.png]]

#### pwndbg

1. **安装 GDB**： 确保你的系统上已经安装了 GDB。如果没有，你可以通过你的包管理器来安装它。例如，在 Ubuntu 上，你可以使用以下命令：
    
    ```text
    sudo apt-get install gdb
    ```
    
2. **下载 `pwndbg`**： 你可以从 `pwndbg` 的 GitHub 仓库下载源代码。使用 `git` 克隆仓库：
    
    ```text
    git clone https://github.com/pwndbg/pwndbg.git
    cd pwndbg
    ```
    
3. **安装 `pwndbg`**： `pwndbg` 提供了一个安装脚本，你可以运行它来安装 `pwndbg`：
    
    ```text
    ./.install
    ```
    
    这个脚本会将 `pwndbg` 所需的脚本和配置文件安装到你的 GDB 目录中。
    
4. **配置 GDB**： 你可能需要在你的 `~/.gdbinit` 文件中添加以下行来启用 `pwndbg`：
    
    ```text
    source /path/to/pwndbg/gdbinit
    ```
    
    确保替换 `/path/to/pwndbg/` 为你的 `pwndbg` 安装路径。
    
5. **验证安装**： 启动 GDB 并输入 `pwn`，如果 `pwndbg` 安装成功，你将看到 `pwndbg` 的提示符。

请注意，`pwndbg` 是为 GDB 定制的，所以你需要确保你的系统中安装了 GDB，并且 GDB 的版本与 `pwndbg` 兼容。如果你遇到任何问题，可以查看 `pwndbg` 的 GitHub 仓库中的 `README` 文件，里面可能有更详细的安装说明和故障排除指南。

---



==对于一些命令可能在pwndbg与pwngdb上的一个不能用，这个时候就是可以使用他们他们两个的联合使用==。

具体安装看这篇文章：[pwngdb+pwngef+peda三合一+pwngdb+pwndbg联合使用_peda mips-CSDN博客](https://blog.csdn.net/qq_39153421/article/details/115386527)
