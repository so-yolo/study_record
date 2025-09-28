```docker
docker run --privileged -it --name ubuntu16 ubuntu:16.04 /bin/bash
```

```
apt-get update
apt-get install -y git
apt-get install vim -y
```

```
vim /etc/apt/sources.list
```

```
deb http://mirrors.aliyun.com/ubuntu/ xenial main  
deb-src http://mirrors.aliyun.com/ubuntu/ xenial main  
  
deb http://mirrors.aliyun.com/ubuntu/ xenial-updates main  
deb-src http://mirrors.aliyun.com/ubuntu/ xenial-updates main  
  
deb http://mirrors.aliyun.com/ubuntu/ xenial universe  
deb-src http://mirrors.aliyun.com/ubuntu/ xenial universe  
deb http://mirrors.aliyun.com/ubuntu/ xenial-updates universe  
deb-src http://mirrors.aliyun.com/ubuntu/ xenial-updates universe  
  
deb http://mirrors.aliyun.com/ubuntu/ xenial-security main  
deb-src http://mirrors.aliyun.com/ubuntu/ xenial-security main  
deb http://mirrors.aliyun.com/ubuntu/ xenial-security universe  
deb-src http://mirrors.aliyun.com/ubuntu/ xenial-security universe
```
https://nightrainy.github.io/2020/01/07/pwn%E7%8E%AF%E5%A2%83docker%E5%8C%96/

```
git clone https://github.com/nightRainy/Pwn_environment_automatically_build_script.git  
cd Pwn_environment_automatically_build_script  
chmod +x setup.sh  
./setup.sh
```

```
root@98c01766c4db:~# touch .tmux.conf  
root@98c01766c4db:~# echo 'set -g mouse on' > .tmux.conf
```


==下面的链接是讲解为何gdb调试不了文件==
[Error disabling address space randomization: Operation not permitted - bonelee - 博客园](https://www.cnblogs.com/bonelee/p/13759054.html)

我感觉是还是上面的那个链接的好使用，下面的这个没什么用
[在Docker内部使用gdb调试器报错-Operation not permitted - 知乎](https://zhuanlan.zhihu.com/p/695713383)

关于联合使用
[gdb调试 | pwndbg+pwndbg联合使用 - 灰信网（软件开发博客聚合）](https://www.freesion.com/article/7871636857/)


这篇文章没有解决gdb的问题（gdb很原始，一些pwn的调试命令用不了）
对于如何搭建我需要的环境见另一篇文章。
