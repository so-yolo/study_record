
#### **一、运作原理**

1. **Fastbin 特性**  
   - 管理小内存块（如 0x20-0x80 字节），使用单向链表（LIFO）。
   - 释放时检查 `chunk == fastbin->fd`，防止连续释放同一 chunk（但可通过 `A→B→A` 绕过）。

2. **malloc_consolidate 的作用**  
   - 当分配大内存（≥0x400）或释放超大块（≥65536）时触发。
   - 遍历所有 fastbin，合并相邻空闲块并迁移到 unsorted bin，破坏 fastbin 的循环链表结构。

3. **漏洞核心**  
   - 通过 `malloc_consolidate` 破坏 fastbin 的循环链表后，可绕过 double free 检查，实现同一内存的重复分配。

---

#### **二、攻击流程示例**
```c
// 1. 构造 fastbin 循环链表
void *A = malloc(0x20); // fastbin chunk (0x30)
void *B = malloc(0x20);
free(A); free(B); free(A); // fastbin: A→B→A

// 2. 触发 malloc_consolidate
void *large = malloc(0x400); // 迁移 A、B 到 unsorted bin

// 3. 重新分配同一内存
void *p1 = malloc(0x20); // 分配 A
void *p2 = malloc(0x20); // 分配 B
void *p3 = malloc(0x20); // 再次分配 A（p1 == p3）
```

---

#### **三、关键点与绕过条件**
| 关键点                | 绕过条件                                                                 |
|-----------------------|--------------------------------------------------------------------------|
| **循环链表构造**       | 释放顺序需为 `free(A); free(B); free(A)`                                 |
| **触发 consolidate**  | 分配大内存（≥0x400）或释放超大块（≥65536）                              |
| **绕过 tcache**       | glibc ≥2.26 时，需先填满 tcache（7/7）迫使分配走 fastbin                |
| **size 字段校验**     | 伪造的 chunk 需满足 `size` 对齐且属于 fastbin 范围（如 0x20-0x80）      |

---

#### **四、现代 glibc 的缓解措施**
1. **tcache (glibc ≥2.26)**  
   - 每个线程的缓存，优先处理小内存请求，检测 double free（通过 `key` 字段）。
   - **绕过方法**：填满 tcache（如分配 7 次）迫使请求进入 fastbin。

2. **safe linking (glibc ≥2.32)**  
   - 对 fastbin 的 `fd` 指针加密：`fd = (real_fd >> 12) ^ &main_arena`。
   - **绕过方法**：需泄漏堆地址或暴力破解。

3. **更严格的 size 检查**  
   - 分配时验证 `size` 字段是否合法（如对齐、范围）。

---

#### **五、总结**
| 维度               | 说明                                                                 |
|--------------------|----------------------------------------------------------------------|
| **适用版本**       | glibc <2.26（无 tcache）或结合 tcache 耗尽技术                      |
| **利用效果**       | 实现 UAF、任意地址分配（如修改 `__malloc_hook`）                     |
| **防御手段**       | tcache 检测、safe linking、ASLR/PIE                                 |
| **现实意义**       | 主要用于 CTF 和漏洞研究，现代系统需结合其他漏洞（如堆泄漏）          |

**完整利用链示例**：  
1. 构造 fastbin 循环链表 → 2. 触发 consolidate → 3. 修改 `fd` 指向目标地址 → 4. 分配并控制目标内存。



#### 六、how2heap源码分析
```markdown
/*
原文参考：https://valsamaras.medium.com/the-toddlers-introduction-to-heap-exploitation-fastbin-dup-consolidate-part-4-2-ce6d68136aa8

本文主要用于演示 `malloc_consolidate` 的机制，以及如何通过双重释放（Double Free）结合该机制，
获取指向同一大尺寸内存块（large-sized chunk）的两个指针。由于 `previnuse` 检查的存在，
直接实现这一目标通常较为困难。

`malloc_consolidate`（源码链接：https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L4714）
的核心功能是合并所有 fastbin 块与它们的相邻空闲块，将其放入 unsorted bin，
并在可能的情况下与 top chunk 合并。

在 glibc 2.35 版本中，该函数仅在以下五处被调用：
1. **_int_malloc**：当分配一个大尺寸内存块时触发（源码链接：https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L3965）
2. **_int_malloc**：当未找到合适 bin 且 top chunk 过小时触发（源码链接：https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L4394）
3. **_int_free**：当释放的块大小 >= `FASTBIN_CONSOLIDATION_THRESHOLD` (65536) 时触发（源码链接：https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L4674）
4. **mtrim**：始终调用（源码链接：https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L5041）
5. **__libc_mallopt**：始终调用（源码链接：https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L5463）

我们将重点针对第 1 种场景，因此需要分配一个不属于 small bin 的内存块
（即需绕过此处的 `else` 分支检查：https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L3901）。
这意味着目标块的尺寸需满足 `size >= 0x400`（即大尺寸块）。

*/
```

```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
int main() {
    printf("This technique will make use of malloc_consolidate and a double free to gain a UAF / duplication of a large-sized chunk\n");
    void* p1 = malloc(0x40);
    void* p2 = malloc(0x40);
    printf("Allocate a fastbin chunk p1=%p \n", p1);
    printf("Freeing p1 will add it to the fastbin.\n\n");
    free(p1);
    void* p3 = malloc(0x400);
    printf("To trigger malloc_consolidate we need to allocate a chunk with large chunk size (>= 0x400)\n");
    printf("which corresponds to request size >= 0x3f0. We will request 0x400 bytes, which will gives us\n");
    printf("a chunk with chunk size 0x410. p3=%p\n", p3);
    printf("\nmalloc_consolidate will merge the fast chunk p1 with top.\n");
    printf("p3 is allocated from top since there is no bin bigger than it. Thus, p1 = p3.\n");
    // assert(p1 == p3);
    printf("We will double free p1, which now points to the 0x410 chunk we just allocated (p3).\n\n");

    free(p1); // vulnerability
    return 0;

}
```

当还没有运行到第一次malloc的时候就出现了一块0x410的大小，也不知道哪来的，等后续研究知道了再回来讲解。
![[Pasted image 20250406112303.png]]

这是运行完两次malloc的时候，
![[Pasted image 20250406112357.png]]

这是运行完free第一次的时候
![[Pasted image 20250406112439.png]]

这是第一次malloc(0x400)的时候
![[Pasted image 20250406112547.png]]


这是第二次运行free的时候
![[Pasted image 20250406112635.png]]

分析：
我们可以看到申请了两个malloc(0x40)的chunk空间，当第一次free的时候p1进入fastbin,
紧接着进行malloc(0x400)的大小，这个时候满足_int_malloc调用malloc_consolidate的条件，会进行合并。
具体流程：首先会去fastbin中将空闲chunk拿来向前或是向后合并（相邻才行），然后拿到unsortedbin中，看看合并后的是否满足所申请的大小，不满足就将unsortedbin中的chunk拿到对应的bin中，反正不能再放回fastbin中了，然后就去largebin中寻找适合的大小，没有的话就去topchunk中切割。
经过这个流程后，p1就跑到smallbin里面了，当我们这个时候fastbin的首地址是空的，也就是说我们再次进行free p1的时候就可以再次将p1的chunk地址拿到fastbin中。
这就实现了P1的地址同时出现在了fastbin和smallbin中。


---


#### 七、_int_malloc调用malloc_consolidate的详细条件
`_int_malloc`调用`malloc_consolidate`的条件可以总结如下：

1. **分配大块内存时**：当请分配的内存大小大于等于0x400字节时，如果存在fast bin中的空闲chunk，`_int_malloc`会调用`malloc_consolidate`来合并fast bin中的chunk，并将它们放入unsorted bin中。

2. **没有找到适合的bin且top太小时**：如果在small bin、fast bin和large bin中都没有找到合适的chunk，并且top chunk的大小不足以满足请求，`_int_malloc`会调用`malloc_consolidate`来合并fast bin中的chunk，以减少堆中的碎片。

3. **small bin为空时**：当请求分配的内存大小在small bin范围内，但small bin为空时，`_int_malloc`会调用`malloc_consolidate`来合并fast bin中的chunk，并尝试重新分配small bin chunk或large bin chunk。

4. **开启ATOMIC_FASTBINS优化时**：如果开启了ATOMIC_FASTBINS优化，当释放属于fast bins的chunk时不需要获得分配区的锁，因此在调用`_int_malloc`函数时，有可能有其他线程已经向fast bins中加入了新的空闲chunk。此时，`_int_malloc`会调用`malloc_consolidate`来合并这些新加入的chunk。

5. **合并后的chunk大小大于FASTBIN_CONSOLIDATION_THRESHOLD**：如果合并后的chunk大小大于等于FASTBIN_CONSOLIDATION_THRESHOLD（通常是65536字节），则会触发`malloc_consolidate`函数来合并fast bins中的空闲chunk到unsorted bin中。

综上所述，`_int_malloc`调用`malloc_consolidate`的主要条件包括分配大块内存、small bin为空、top chunk太小以及开启ATOMIC_FASTBINS优化等情况下，以确保内存管理的高效性和减少内存碎片。



#### 八、学习中出现的疑惑
