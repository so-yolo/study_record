在堆漏洞利用中，**`fastbin_dup`** 是一种经典的 **double free** 攻击技术，它通过构造特定的内存释放顺序，绕过 `glibc` 对 fastbin 的双重释放（double free）的检查，最终实现内存的重复分配与控制。以下是其核心机制和实现原理：

---

### 一、`fastbin_dup` 的运作原理
#### 1. **Fastbin 的释放规则**
- Fastbin 是一个 **LIFO（后进先出）** 的单向链表，释放 chunk 时会将新释放的 chunk 插入链表头部。
- **检查机制**：==释放一个 chunk 时，`glibc` 仅检查该 chunk **是否与当前链表头的 chunk 相同**（防止连续两次释放同一 chunk）。==

#### 2. **绕过检查的关键**
通过 **中间插入其他 chunk**，构造如下释放顺序：
```
free(A) → free(B) → free(A)
```
- 第一次 `free(A)`：链表头为 `A`，链表结构为 `A → NULL`。
- 第二次 `free(B)`：链表头更新为 `B`，链表结构变为 `B → A → NULL`。
- 第三次 `free(A)`：检查链表头 `B` 是否等于 `A`（不相等），释放成功，链表变为 `A → B → A → ...`，形成循环。
- 
#### 3.检查措施的源码
```c
if (__builtin_expect (old == p, 0)) {  // old 是当前链表头，p 是待释放的 chunk
    errstr = "double free or corruption (fasttop)";
    goto errout;
}
```

#### 4. **最终效果**
- Fastbin 链表中出现环状结构（`A → B → A`），后续分配时可多次获取同一内存块（如 `A`），导致 **内存重叠**，为漏洞利用（如修改函数指针、覆盖数据）提供可能。

---

### 二、攻击流程示例（基于 `glibc < 2.26`）
#### 1. 代码示例
```c
#include <stdlib.h>

int main() {
    void *A = malloc(0x20);  // 分配 fastbin chunk（假设大小为 0x20）
    void *B = malloc(0x20);

    free(A);                 // 第一次释放 A → fastbin: A → NULL
    free(B);                 // 释放 B → fastbin: B → A → NULL
    free(A);                 // 再次释放 A → fastbin: A → B → A → ...

    // 后续分配：
    void *p1 = malloc(0x20); // 返回 A
    void *p2 = malloc(0x20); // 返回 B
    void *p3 = malloc(0x20); // 再次返回 A（此时 p1 == p3）
    return 0;
}
```

#### 2. 内存布局变化
```
初始状态：
Fastbin[0x30]: NULL

释放 A 后：
Fastbin[0x30]: A → NULL

释放 B 后：
Fastbin[0x30]: B → A → NULL

释放 A 后：
Fastbin[0x30]: A → B → A → B → ...（循环链表）
```

---

### 三、关键点与绕过条件
#### 1. **Chunk 大小限制**
- 所有涉及的 chunk 必须属于同一 fastbin 大小范围（例如 0x20、0x30 等），否则会被分配到不同的 fastbin 链表。

#### 2. **绕过检查的必备操作**
- **插入中间 chunk**：必须确保在两次释放同一 chunk 之间释放另一个 chunk，使链表头发生变化。

#### 3. **利用场景**
- **UAF（Use-After-Free）**：通过多次分配同一内存块，实现不同指针操作同一内存区域。
- **控制关键数据**：如覆盖堆上的函数指针、修改 `tcache` 或 `fastbin` 链表指针。

---

### 四、现代 glibc 的缓解措施（>= 2.26）
#### 1. **tcache 的引入**
- **严格检查**：tcache 会记录每个 chunk 的释放状态（通过 `key` 字段），直接检测重复释放。
  ```c
  // glibc 源码（malloc/malloc.c）
  if (tcache->entries[tc_idx] == p) {  // 检查是否已存在于 tcache
      return;                          // 拒绝释放
  }
  ```
- **绕过难度**：需先清空 tcache 或覆盖 `key` 字段才能触发 fastbin 的 double free。

#### 2. **安全增强**
- **`fasttop` 检查强化**：新版本可能增加对链表的遍历检查（但仍非全局）。

---

### 五、防御与检测
#### 1. **代码层面**
- 避免对同一指针多次 `free`。
- 使用内存检测工具（如 AddressSanitizer、Valgrind）捕获 double free。

#### 2. **堆布局防护**
- 随机化堆地址（ASLR）、隔离敏感数据。

---

### 六、总结
| 技术要点          | 说明                                                                 |
|-------------------|----------------------------------------------------------------------|
| **攻击条件**       | glibc < 2.26，fastbin 同一大小，插入中间 chunk 绕过检查。            |
| **利用效果**       | 构造循环链表，实现内存重复分配，引发 UAF 或数据覆盖。                |
| **现代绕过**       | 需结合 tcache 耗尽或 `key` 字段篡改（如 `house of botcake` 等攻击）。|
| **防御重点**       | 更新 glibc、启用安全机制（如 tcache 检测）、代码审计。               |

**注**：`fastbin_dup` 是理解堆漏洞利用的基础，但其在现代环境中的直接应用已受限，需结合其他技术（如 tcache 攻击）实现完整利用链。


### 七、how2heap代码分析

源码如下
```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
int main()
{
    fprintf(stderr, "This file demonstrates a simple double-free attack with fastbins.\n");
    fprintf(stderr, "Allocating 3 buffers.\n");
    int *a = malloc(8);
    int *b = malloc(8);
    int *c = malloc(8);
    fprintf(stderr, "1st malloc(8): %p\n", a);
    fprintf(stderr, "2nd malloc(8): %p\n", b);
    fprintf(stderr, "3rd malloc(8): %p\n", c);
    fprintf(stderr, "Freeing the first one...\n");
    free(a);
    fprintf(stderr, "If we free %p again, things will crash because %p is at the top of the free list.\n", a, a);
    // free(a);
    fprintf(stderr, "So, instead, we'll free %p.\n", b);
    free(b);
    fprintf(stderr, "Now, we can free %p again, since it's not the head of the free list.\n", a);
    free(a);
    fprintf(stderr, "Now the free list has [ %p, %p, %p ]. If we malloc 3 times, we'll get %p twice!\n", a, b, a, a);

    a = malloc(8);
    b = malloc(8);
    c = malloc(8);
    fprintf(stderr, "1st malloc(8): %p\n", a);
    fprintf(stderr, "2nd malloc(8): %p\n", b);
    fprintf(stderr, "3rd malloc(8): %p\n", c);
    assert(a == c);

}
```

运行结果如下
![[Pasted image 20250405195852.png]]

![[Pasted image 20250405195755.png]]

这一题我是编译成的64位的

分析：
源码时显示我们申请了三块8字节的堆空间，使用的是brk方式申请的，因为我们是64位的架构，我们申请的数据是满足0x10字节的整数倍的且最小得是0x20(因为我们加上0x8字节就0x18了)，也就是说我们可以申请0x20,0x30,0x40.....等等，当我们的申请的数据不满足这个规则的时候我们的数据就会被分配至满足规则的数据大小。glibc根据规则会给我们添加的是一个元数据也就是数据头0x10字节，然后再加上我们原本的字节数，看看是否满足整数的规则，不满足就会再给我们多分配点至满足。
![[Pasted image 20250405201349.png]]

我们可以看到上面分配的三块大小的堆地址之间的距离是0x20字节的大小，我们分析一下，0x20=0x8+0x10+0x8(多分配的空间)，这样一看就明了了，如上图，元数据就是前两行的pre size空间和size空间的大小。


当我运行完第三个free的时候，我们可以看到我们的
![[Pasted image 20250405201758.png]]

这个图是各堆的详细信息
![[Pasted image 20250405201935.png]]

分配完这三个空间的后堆空间以及当开始free(a),free(b)后是这样的
![[Pasted image 20250405203822.png]]

chunk c 的地址后面就是top chunk的地址，这是根据上面gdb调试出来的画的图。chunk c, chunk a, chunk b原本在堆空间的地址以及他们的下一个堆空间地址fd指针都有显示。
当我们free a的时候我们的0x20字节空间就会跑到fastbin中，free b的时，因为是相同的0x20大小，所以就会放在同一个大小的fastbin单链表里，且是在chunk a的前面，因为fastbin是LIFO的规则。
所以我们就可以发现依次是这样的
![[Pasted image 20250405204917.png]]

![[Pasted image 20250405204956.png]]

检测double free的规则是拿我们要free的空间的地址去和对应size大小的fastbin链表中的首个chunk的地址比较是否一样，一样的话就aborted。
 因此我们只需要再在free a的中间再free一个不一样的chunk就行，这是free b,就能达成这个绕过。
 ![[Pasted image 20250405210435.png]]
 
 判断通过后就是这样的就够
![[Pasted image 20250405205828.png]]


