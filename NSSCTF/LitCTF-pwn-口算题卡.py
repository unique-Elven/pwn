from pwn import *
p = remote("node4.anna.nssctf.cn",29000)
context(os="linux",arch="i386",log_level='debug')
p.recvuntil(b"Have fun!")
for i in range(100):
    p.recvuntil(b"What is ")
    key = p.recvuntil(b"?")
    payload = str(eval(key[:-1]))
    print(str(key[:-1])+'='+payload)
    p.sendline(payload)
p.interactive()




