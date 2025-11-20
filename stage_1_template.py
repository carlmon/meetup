#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'

elf = ELF('./<BINARY NAME HERE>')
CMD = ['c']

t = gdb.debug(elf.file.name, '\n'.join(CMD))
# t = process(elf.file.name)
# t = remote('<IP ADDRESS>', <PORT>)

# t.recvuntil()

buf = b'<PAYLOAD HERE>'
t.sendline(buf)

t.interactive()
