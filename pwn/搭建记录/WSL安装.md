注意：本文是在win11系统下安装wsl2

## 一 ，安装步骤：

#### 1. 打开PowerShell作为管理员，执行以下命令，以启用WSL特性：

```
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
```

#### 2.然后，执行以下命令以启用虚拟机平台：

```
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
```

#### 3.通过设置安装 WSL

1. 在搜索栏中输入“控制面板”，打开“程序”，打开“启用或关闭windows功能”，然后如图勾选。

![[Pasted image 20240923213324.png]]

![[Pasted image 20240923213333.png]]

![[Pasted image 20240923213350.png]]

#### 4.然后，下载以下更新包：

[WSL 2 Linux kernel update package for x64 machines](https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi)

#### 5.安装完升级包后，将WSL 2设置为默认版本：

```
wsl --set-default-version 2
```

#### 6.下载并安装WSL2 Linux内核更新包，从以下链接中下载：

[WSL 2 Linux kernel update package for x64 machines](https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi)

#### 7.安装完升级包后，将WSL 2设置为默认版本：

```
wsl --set-default-version 2
```

#### 8.最后，在PowerShell提示符下，输入以下命令以安装适用于WSL的Linux发行版：

```
wsl --install  
```

或在Microsoft Store中，搜索你想要的支持WSL的Linux发行版，然后安装它。

#### 9.然后重启。
[WSL win11下 Linux 子系统安装 无法解析服务器的名称或地址_适用于 linux 的 windows 子系统已安装。 无法解析服务器的名称或地址-CSDN博客](https://blog.csdn.net/weixin_45827203/article/details/129089649)

## 二，问题解决：

我自己遇到的问题是：打开安装的Ubuntu后输入任意数会瞬间跳出程序，我试过了网站上的大部分方法，但都无法就解决问题，最后是执行了这条命令解决的，用管理员权限执行：

```
bcdedit /set hypervisorlaunchtype Auto
```

问题迎刃而解！！！

具体问题解决原理可看此文（文章转载于）：[https://blog.csdn.net/qq_39757730/article/details/117431647](https://blog.csdn.net/qq_39757730/article/details/117431647)

## 三、关于c盘ubuntu迁移d盘解决办法
[在 Win11安装 Ubuntu20.04子系统 WSL2 到其他盘（此处为D盘，因为C盘空间实在不能放应用）_wsl2安装ubantu到d盘-CSDN博客](https://blog.csdn.net/orange1710/article/details/131904929)