import angr

main = 0x4007C2
find = 0x404FC1
avoid = [0x4005E0]

p = angr.Project('./angrybird')
init = p.factory.blank_state(addr=main)
pg = p.factory.path_group(init, threads=8)
ex = pg.explore(find=find, avoid=avoid)

final = ex.found[0].state
flag = final.posix.dumps(0)
print flag
print("Flag: {0}".format(final.posix.dumps(1)))
