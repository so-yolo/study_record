#### Scoop 安装 Git

```
Set-ExecutionPolicy RemoteSigned -scope CurrentUser
iwr -useb get.scoop.sh | iex
```

```
scoop install git
```

```
git config --global user.name "so-yolo"  
git config --global user.email "2088469395@qq.com"
```

```
ssh-keygen -t rsa -C "2088469395@qq.com"
```

将生成的id.rsa.pub的密钥，放在key里
![[Pasted image 20240920213021.png]]

![[Pasted image 20240920213159.png]]

然后假设你的笔记仓库名为obdocs

```
git init 
git add obdocs
git commit -m "first commit" 
git remote add origin git@github.com:xxx/testgit.git     #这里替换成自己的仓库
git push -u origin master
```

然后 git clone ssh里面的链接