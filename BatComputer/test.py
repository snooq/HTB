#!/usr/bin/python
import sys

leak="0xffffffffffffdf04"
addr = int(leak, 16) 

#byte_array=bytearray.fromhex(addr)

print (sys.maxsize)
print (addr)

