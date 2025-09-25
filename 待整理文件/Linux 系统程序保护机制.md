# Linux 系统程序保护机制

Linux 系统和编译器实现了多种程序保护机制，用于防御缓冲区溢出、内存漏洞利用（如 UAF、Double Free）、控制流劫持等常见攻击。这些机制从**内存布局、代码执行、权限控制**等多个层面提供保护，以下是核心机制的详细说明：

### 一、内存布局随机化（ASLR，Address Space Layout Randomization）



*   **作用**：通过随机化程序关键内存区域的基地址，使攻击者难以预测函数、栈、堆的位置，从而阻止基于固定地址的漏洞利用（如硬编码跳转地址）。

*   **保护范围**：


    *   栈（stack）：栈的起始地址随机化；

    *   堆（heap）：堆的起始地址和分配内存块的位置随机化；

    *   共享库（shared libraries）：动态链接库（如 `libc.so`）的加载地址随机化；

    *   程序自身（需配合 PIE）：可执行文件的代码段、数据段地址随机化。

*   **实现方式**：


    *   内核通过 `/proc/sys/kernel/randomize_va_space` 控制 ASLR 强度（0 = 关闭，1 = 部分随机化，2 = 完全随机化，默认值为 2）；

    *   需程序编译为 **PIE（Position-Independent Executable）** 才能使自身代码段随机化（编译时加 `-fPIE -pie` 选项）。

### 二、栈保护（Stack Protection）

针对栈溢出攻击（如通过 `strcpy` 等函数覆盖返回地址），编译器实现了多种栈保护机制：

#### 1. 金丝雀（Stack Canary / StackGuard）



*   **原理**：在栈上的返回地址与局部变量之间插入一个随机生成的 “金丝雀” 值（canary），函数返回前检查该值是否被篡改。若被修改（通常是栈溢出导致），则立即终止程序。

*   **实现**：


    *   编译时加 `-fstack-protector`（对包含栈缓冲区的函数启用）或 `-fstack-protector-all`（对所有函数启用）；

    *   金丝雀值通常存储在 `%fs:0x28`（x86\_64）等特殊寄存器 / 内存中，攻击者难以提前预测。

#### 2. 栈不可执行（NX Stack / SX Stack）



*   **原理**：标记栈内存页为 “不可执行”（Non-eXecutable），防止攻击者向栈中注入 shellcode 并执行（栈溢出后即使覆盖返回地址指向 shellcode，也会因权限不足而失败）。

*   **实现**：


    *   本质是 CPU 页表的权限控制（通过 `NX` 标志位），由内核与编译器配合启用；

    *   编译时默认启用（现代编译器如 GCC/Clang 无需额外选项），可通过 `-z execstack` 强制关闭（不推荐）。

### 三、全局偏移表保护（RELRO，Read-Only Relocations）

针对**GOT 劫持**攻击（通过修改全局偏移表 `GOT` 中的函数地址，将库函数调用重定向到恶意代码），RELRO 限制 `GOT` 的可写性：



*   **部分 RELRO（Partial RELRO）**：


    *   初始化 `GOT` 后，将其设置为只读（防止动态链接完成后被修改），但 `GOT` 中的未解析项仍可写（动态链接过程中需更新）；

    *   编译时加 `-z relro` 启用，默认情况下多数程序会启用。

*   **完全 RELRO（Full RELRO）**：


    *   动态链接完成后，`GOT` 被完全标记为只读，且 `plt` 表（过程链接表）也被固化，彻底阻止 `GOT` 篡改；

    *   同时会重排程序的 `.ctors`/.`dtors`（构造 / 析构函数表），防止通过覆盖这些表劫持控制流；

    *   编译时加 `-z relro -z now` 启用（`-z now` 表示强制提前解析所有符号，无需延迟绑定）。

### 四、数据执行保护（DEP，Data Execution Prevention）



*   **作用**：区分 “数据页” 和 “代码页”，仅允许代码页（如 `.text` 段）执行指令，数据页（栈、堆、`.data` 段）默认不可执行，防止攻击者在数据区注入并执行恶意代码。

*   **实现**：


    *   依赖 CPU 硬件支持（如 x86 的 `NX` 位、ARM 的 `XN` 位），内核通过页表权限控制实现；

    *   是栈不可执行（NX Stack）的扩展，覆盖所有内存区域（堆、数据段等）。

### 五、控制流完整性（CFI，Control-Flow Integrity）



*   **作用**：限制程序的控制流只能沿 “预期路径” 执行，防止通过漏洞（如 UAF、缓冲区溢出）篡改函数指针、返回地址等，劫持控制流到非预期位置（如 shellcode）。

*   **实现方式**：


    *   **编译器插桩**：Clang 的 `ControlFlowIntegrity`（编译时加 `-fsanitize=cfi`）会在函数调用前检查目标地址是否为合法函数入口；

    *   **硬件辅助**：Intel 的 CET（Control-Flow Enforcement Technology）通过 “影子栈”（Shadow Stack）记录合法返回地址，防止返回地址被篡改；

    *   **间接跳转检查**：对间接函数调用（如通过函数指针）验证目标是否在预定义的 “合法函数列表” 中。

### 六、malloc 保护机制（堆保护）

针对堆漏洞（如 UAF、Double Free、堆溢出），glibc 等内存分配器实现了多种保护：



1.  **tcache 检查（glibc 2.26+）**：

*   tcache（线程缓存）是小型内存块的分配池，释放时会检查内存块是否已在 tcache 中（防止 Double Free），分配时验证块大小是否匹配（防止堆溢出覆盖元数据）。

1.  **chunk 元数据校验**：

*   堆块（chunk）的元数据（如 `size` 字段）中包含 “prev\_inuse” 等标志位，分配 / 释放时检查标志位合法性（防止伪造堆块）；

*   大内存块（如进入 unsorted bin）释放时会检查相邻块是否空闲（防止合并攻击）。

1.  **malloc 钩子保护**：

*   `__malloc_hook`、`__free_hook` 等全局钩子函数在高版本 glibc 中被移除或限制，防止通过篡改钩子劫持内存分配流程。

### 七、系统调用限制（seccomp）



*   **作用**：限制程序可调用的系统调用（syscall）类型，减少攻击面（即使攻击者劫持控制流，也无法调用危险系统调用如 `execve` 执行命令）。

*   **实现**：


    *   程序可通过 `prctl(PR_SET_SECCOMP, ...)` 启用 seccomp 模式，常用 “严格模式”（仅允许 `read`、`write`、`exit`、`sigreturn`）或 “过滤模式”（通过 BPF 规则自定义允许的系统调用）；

    *   沙箱环境（如 Docker、Chrome 沙箱）广泛使用 seccomp 限制程序权限。

### 八、其他保护机制



1.  **PIE（Position-Independent Executable）**：

*   使可执行文件本身成为 “位置无关代码”，加载时基地址随机化（配合 ASLR 使代码段地址不可预测），编译时需加 `-fPIE -pie`。

1.  **FORTIFY\_SOURCE**：

*   对危险函数（如 `strcpy`、`memcpy`）进行增强，编译时检查缓冲区大小（如 `strcpy` 替换为 `__strcpy_chk`，验证目标缓冲区是否足够大），防止简单的缓冲区溢出。

*   编译时加 `-D_FORTIFY_SOURCE=2` 启用（需配合 `-O` 优化选项）。

1.  **内存页权限控制**：

*   内核通过 `mprotect` 系统调用允许程序动态修改内存页权限（如将数据页设置为 `PROT_READ | PROT_WRITE`，代码页设置为 `PROT_READ | PROT_EXEC`），防止非预期的权限滥用。

