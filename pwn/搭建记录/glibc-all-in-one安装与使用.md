
下载

```
#Patchelf
git clone https://github.com/NixOS/patchelf

#glibc-all-in_one
git clone https://github.com/matrix1001/glibc-all-in-one
```

命令：

```
./update_list #更新最新版本的glibc
 cat list #查看可下载的glibc
```

查看list中的glibc的版本

![[Pasted image 20240923213134.png]]

![[Pasted image 20240923213142.png]]

如果题目附件没有给ld文件，可以通过执行libc.so.6获取glibc版本

![[Pasted image 20240923213150.png]]

==不过这样一般也不行，还有一种方法：==

```
strings libc.so.6 |grep GLIBC
```



下载libc

```
./download 2.23-0ubuntu11.3
```

![[Pasted image 20240923213200.png]]

查看题目原来的 libc 和 ld

```
ldd easyheap
#下面是我已经链接过的了
```

![[Pasted image 20240923213212.png]]

再根据题目所给的 glibc ，找对应版本的连接器

```
patchelf --set-interpreter /home/yolo/glibc-all-in-one/libs/via/ld-2.34.so easy_heap
```

```
patchelf --replace-needed ./libc.so.6 /home/yolo/glibc-all-in-one/libs/
via/libc.so.6 easy_heap
#前面的libc.so.6是原本的，后面的是需要替换成的
```

如果是还是没有权限的话，就将glibc的ld文件和.so文件加权限。
![[Pasted image 20240923213222.png]]

参考文献：[https://sillyrabbit.cn/pwn/patchif%E5%92%8Cglibc-all-in_one%E4%BD%BF%E7%94%A8%E7%AC%94%E8%AE%B0/](https://sillyrabbit.cn/pwn/patchif%E5%92%8Cglibc-all-in_one%E4%BD%BF%E7%94%A8%E7%AC%94%E8%AE%B0/)