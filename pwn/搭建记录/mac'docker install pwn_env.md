```
docker pull --platform linux/amd64 ubuntu:22.04
docker run --platform linux/amd64 -v /Users/a1/Desktop/pwn:/pwn --privileged -it --name ubuntu22.04_gdb ubuntu:22.04 /bin/bash
```

```
apt-get update
apt-get install -y git
apt-get install vim -y
```

```bash
apt update -y 
apt install -y build-essential libc6-dev-i386 gdb gdb-multiarch binutils strace ltrace file ruby git vim netcat-traditional tmux python3 python3-pip python3-dev libssl-dev libffi-dev 
pip3 install --upgrade pip 
pip3 install pwntools ropper pwndbg capstone keystone-engine unicorn 
gem install one_gadget 
git clone https://github.com/pwndbg/pwndbg.git /opt/pwndbg 
cd /opt/pwndbg 
git checkout 2023.05.01 
./setup.sh 
cd ~ 
git clone https://github.com/longld/peda.git /opt/peda 
echo "source /opt/pwndbg/gdbinit.py" > ~/.gdbinit 
apt install -y ropgadget 
git clone https://github.com/slimm609/checksec.sh.git /opt/checksec 
ln -s /opt/checksec/checksec /usr/local/bin/checksec 
gdb --version | head -1 
python3 -c "from pwn import *; print('pwntools 已安装')" 
one_gadget --version | head -1 
checksec --version
```

```
vim ~/.gdbinit
# source /opt/peda/peda.py # 注释掉 peda（暂时禁用

apt install -y qemu-user qemu-user-static
cd /pwn/2024hnctf/h&nctf_pwn/ez_pwn/

qemu-i386 -g 1234 ./pwn &
gdb-multiarch ./pwn

pwndbg> target remote localhost:1234
b main
c
```

```
查看 qemu 开启的端口
apt install -y net-tools
netstat -tulpn | grep -i qemu
```
