from pwn import *
from LibcSearcher import LibcSearcher
from ctypes import*
import ctypes
def init(file1, file2, x):
    if file2:
        if x:
            return process(file1), ELF(file1), ELF(file2)
        else:
            return remote("node5.buuoj.cn", 26682), ELF(file1), ELF(file2)
    else:
        if x:
            return process(file1), ELF(file1)
        else:
            return remote("node5.buuoj.cn", 26682), ELF(file1)

def log(a, b, c):
    if a:
        context.log_level = "debug"
    if b:
        context.os = 'linux'
    if c:
        context.arch = 'amd64'

def debug():
    attach(p)

r = lambda x: p.recv(x)
ru = lambda str: p.recvuntil(str)
rul1 = lambda: u64(p.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))
rul2 = lambda: u64(p.recvuntil('\n')[:-1].ljust(8, b'\x00'))
s = lambda str: p.send(str)
sl = lambda str: p.sendline(str)
sa = lambda a, b: p.sendafter(a, b)
sla = lambda a, b: p.sendlineafter(a, b)
libc_base = lambda addr, name: addr - libc.dump(name)
go = lambda: p.interactive()

#######################################################################################
log(1, 1, 1)
p, elf = init("./dice_game", 0, 1)
context.terminal = ['tmux', 'splitw', '-h']
# plt, got, sym = [elf.plt['printf'], elf.got['read'], elf.sym['main']]
# debug()
#######################################################################################


go()

