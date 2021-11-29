#!/usr/bin/env python3
from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)

def find_ip(payload):
    # Launch process and send payload
    p = process(exe)
    p.sendlineafter('>', '1')  # Try to buy something
    p.sendlineafter('Enter details:', payload)
    # Wait for the process to crash
    p.wait()
    # Print out the address of EIP/RIP at the time of crashing
    # ip_offset = cyclic_find(p.corefile.pc)  # x86
    ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    info('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset

gdbscript = '''
init-pwndbg
piebase 0x40c0
breakrva 0x1352 
'''.format(**locals())

exe = './pwnshop'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

#offset = find_ip(cyclic(100))

io=process(exe)
io=start()
io.interactive()

