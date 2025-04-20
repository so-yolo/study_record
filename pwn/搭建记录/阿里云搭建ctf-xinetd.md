## 服务器初始化后，密钥未重置

![[Pasted image 20240923212823.png]]

解决方法：

ssh-keygen -R 47.113.97.132

## 下面是安装docker的过程

运行以下命令，下载docker-ce的yum源。

```
sudo wget -O /etc/yum.repos.d/docker-ce.repo https://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo
```

运行以下命令，安装Docker。

```
sudo yum -y install docker-ce
```

但是出错了。错误如下：

![[Pasted image 20240923212833.png]]

解决方法如下：

![[Pasted image 20240923212851.png]]

执行以下命令，检查Docker是否安装成功。

```
docker -v
```

执行以下命令，启动Docker服务，并设置开机自启动。

```
sudo systemctl start docker
sudo systemctl enable docker
```

执行以下命令，查看Docker是否启动

```
sudo systemctl status docker
```

来至文章：[https://help.aliyun.com/zh/ecs/use-cases/install-and-use-docker-on-a-linux-ecs-instance#aa11e8210adyt](https://help.aliyun.com/zh/ecs/use-cases/install-and-use-docker-on-a-linux-ecs-instance#aa11e8210adyt)

## 下面是安装ctf-xinetd的过程

第一步是需要docker的环境，上面已经提到了，这里跳过。

安装好了以后运行命令`sudo docker ps -a`没报错就是成功了。

![[Pasted image 20240923212904.png]]

下面是clone ctf-xinted到本地

git clone https://github.com/Eadom/ctf_xinetd.git

克隆下来之后然后在文件的同级目录建立一个docker-compose.yml的文件

![[Pasted image 20240923212913.png]]

然后将下列信息下入文件中，这里的prot也即是你的后面来连接要使用的端口。后面我们以8888为例。

```
version: '3'

services:
    pwn:
        build: ./
        image: pwn
        ports:
            - "port:9999"
        pids_limit: 1024
        # cpus: 0.5
        restart: unless-stopped
        # privileged: true
```

然后直接打开dockerfile文件，将第一行的ubuntu版本改成你的版本。

将第三个run的内容删去一行。以免后面的麻烦。

![[Pasted image 20240923212925.png]]

将bin文件中的二进制文件名改成你ctf.xinetd中的一致就行,我这儿以pwn为例。
![[Pasted image 20240923212936.png]]
在ctf_xinetd的目录下运行命令：

```
docker build -t "pwn" .



docker run -d -p "0.0.0.0:8090:80" -h "helloworld" --name="helloworld" pwn
```


来创建一个镜像，也就是image，这里的名字要和docker-compose中写的名字一样，也就是说你docker-compose文件里的image名字写的是什么，这里build的image名就要叫啥。

这个是时候可能拉不下来镜像。我们可以换一下镜像代理。

```
sudo mkdir -p /etc/docker
sudo tee /etc/docker/daemon.json <<-'EOF'
{
    "registry-mirrors": [
        "https://docker.m.daocloud.io",
        "https://dockerproxy.com",
        "https://docker.mirrors.ustc.edu.cn",
        "https://docker.nju.edu.cn"
    ]
}
EOF
sudo systemctl daemon-reload
sudo systemctl restart docker
```

测试是否部署成功

nc 127.0.0.1 (port)

这里注意遇到很坑的地方，第一次部署pwn题可能会碰到，就是一定要设置缓冲区，也就是下面的代码,不然无法输出内容，必须先要用户输入才行。

```
__attribute__((constructor))
void setup(void) {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  // alarm(180);
}
```