下载到本地后，进行初始化，下载时间过程时间有点长


```
./get # List categories

./get ubuntu debian # Download Ubuntu's and Debian's libc, old default behavior

./get all # Download all categories. Can take a while!
```


下载的libc存放在db中，之后通过符号和偏移查找libc版本时就会依赖于这个db

## 支持的命令

- find 用于根据符号和偏移查找libc版本，打印libc ID。
- dump 用于转储查到的libc库中的一些常用符号和偏移，也可以通过指定符号转储偏移。
- add 用于手动添加一些libc库到db。
- identify 用于判断某个libc是否已经存在于db，支持hash查找。
- download 用于下载与libc ID相对应的整个libc到libs目录。
- get 下载libc到db，用于初始化于更新libc database。

示例：

在此目录下进行搜索
**![[Pasted image 20240923213245.png]]**
$$

$$
./get # 列出所有分类
./get ubuntu debian # 下载 Ubuntu 和 Debian 的 libc
./get all # 下载所有分类


#### 出错
打开libcSearcher目录下的libcdatabase
#删除libcdatabase里的文件
rm -rf *
#重新安装libcdatabase的东西
git clone https://github.com/niklasb/libc-database
./get ubuntu 
#出现报错Requirements for download or update ‘ubuntu’ are not met. Please, refer to README.md for installation instructions
#安装astd
sudo su 
apt-get install zstd
./get ubuntu


> [!NOTE] libc-database进行patchelf

```

> 1.通过strings libc.so.6 | grep GLIBC进行确定ubuntu的版本

> 2.patchelf --replace-needed libc.so.6 ../../../libc-database/libs/libc6_2.23-0ubuntu11.3_amd64/libc-2.23.so pwn

> 3.patchelf --set-interpreter ../../../libc-database/libs/libc6_2.23-0ubuntu11.3_amd64/ld-2.23.so pwn
```

---
注意：
>
>1.修改ld需要找ld-x.xx.so
>2.修改libc是找libc-x.xx.so，而不是libc.so.6
>3.所需的ld与libc的文件需要在下载的版本文件中修改，不可拿出来修改，否则会文件缺失
>4.附件更改好了ld与libc以后就不要更换文件目录了

[引用于：https://www.cnblogs.com/xshhc/p/16777707.html]