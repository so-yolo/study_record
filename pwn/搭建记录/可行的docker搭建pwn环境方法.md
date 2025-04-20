首先去[roderickchan/debug_pwn_env Tags | Docker Hub](https://hub.docker.com/r/roderickchan/debug_pwn_env/tags)
![[Pasted image 20250405195049.png]]
这里下载我们需要的镜像，这里的镜像是已经集成了一些必要的pwn环境工具，例如gcc,gdb,等等，我们把他拉到本地的docker内，然后再进行docker run +加上自定义的命令就行，例如：

![[Pasted image 20250405193807.png]]

![[Pasted image 20250405193836.png]]

就能将拉取的镜像建立成我们对应版本的容器

![[Pasted image 20250405194121.png]]

我们就能发现我们需要的基本的工具已经在容器内了，这个还得多亏这个作者的自制镜像，我自己配的gdb真的很原始，真的难用。

