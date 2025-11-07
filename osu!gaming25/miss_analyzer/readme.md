# Miss Analyzer

_Disclaimer: I solved this challenge just after the CTF had ended_

```
$ tar xvf pwn_miss-analyzer-v2.tar.gz
dist/
dist/Dockerfile
dist/analyzer
dist/flag.txt
dist/libc.so.6
dist/nsjail.cfg

$ pwn checksec dist/analyzer
[*] '/home/files/dist/analyzer'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

## functionality

This binary was designed to parse an osu! replay (`.osr`) file. In particular,
the contents of the binary data file are to be hexdumped into `stdin`, all on
one line. The binary contains a string specifying the expected usage

```
$ strings analyzer
/lib64/ld-linux-x86-64.so.2
__gmon_start__
seccomp_load
seccomp_release
seccomp_rule_add
seccomp_init
getline

...

Submit replay as hex (use xxd -p -c0 replay.osr | ./analyzer):

...

.data
.bss
.comment
```

Once the input has been read, the hex is decoded to raw bytes for further
processing.

<!-- TODO: write more about the `OSR` file, linking to the OSU wiki with
information on the internally represented data. then link it to the several
functions sprinkled across the binary to parse those items -->

From the replay file alone, the program is able to extract some metadata, namely
the following items.

- Which game type that was played in the replay file. (ie. its mode)
- Its hash, represented by a string
- The player who created the replay file
- The total number of prompts missed within the replay

Each of these data points are printed to the terminal immediately after parsing
that part of the file

Once completed, the program cleans up, and returns. Nothing too fancy beyond
that.

One item that I've been glossing over thus far would be the program's
specification of `seccomp(2)` rules. Two filters are specifically set at the
beginning of the program, which namely are `execve` and `stub_execveat`. This
would namely mean that the program would be disallowed from spawning new
processes. This does not affect anything in our current program flow, but, as a
spoiler, it makes things a little less fun. (\*_cough_\*)

## vulnerabilities

| Address       | Description of Vulnerability  |
|--:            |:--                            |
| 0x0401ada     | There is a call to `printf(3)` that uses an input string of at most 255 bytes in size. This provides both an arbitrary read and an arbitrary write |

... That's it. The entire exploit script needs to revolve around this single
arbitrary read and arbitrary write vulnerability.

## exploitation

Admittedly I was at a loss as the `printf` is only found in the main function
call. This would entail that a chain of base addresses would be unavailable,
blocking an immediate write to a return address. There exist a few additional
details of the binary that we can use to our advantage, which enables everything.

The core details of the binary is that it was compiled as a position
dependent executable and the default compilation with partial RELRO, seen
through the results of `checksec` above. Therefore, the program's addresses, but
not necessarily the libraries it uses, are always predictable. This is not
particularly useful until the global offset table (GOT) is looked at.

```
pwndbg> got
Filtering out read-only entries (display them with -r or --show-readonly)

State of the GOT of /home/user/files/dist/analyzer_patched:
GOT protection: Partial RELRO | Found 16 GOT entries passing the filter
[0x404018] free@GLIBC_2.2.5 -> 0x401030 ◂— endbr64
[0x404020] seccomp_init -> 0x7f0187f86760 (seccomp_init) ◂— endbr64
[0x404028] putchar@GLIBC_2.2.5 -> 0x401050 ◂— endbr64
[0x404030] seccomp_rule_add -> 0x7f0187f87ab0 (seccomp_rule_add) ◂— endbr64
[0x404038] puts@GLIBC_2.2.5 -> 0x7f0187c80e50 (puts) ◂— endbr64
[0x404040] seccomp_load -> 0x7f0187f86f40 (seccomp_load) ◂— endbr64
[0x404048] strlen@GLIBC_2.2.5 -> 0x7f0187d9d860 (__strlen_avx2) ◂— endbr64
[0x404050] __stack_chk_fail@GLIBC_2.4 -> 0x4010a0 ◂— endbr64
[0x404058] printf@GLIBC_2.2.5 -> 0x7f0187c606f0 (printf) ◂— endbr64
[0x404060] seccomp_release -> 0x4010c0 ◂— endbr64
[0x404068] memset@GLIBC_2.2.5 -> 0x7f0187da1000 (__memset_avx2_unaligned_erms) ◂— endbr64
[0x404070] strcspn@GLIBC_2.2.5 -> 0x7f0187d98610 (__strcspn_sse42) ◂— endbr64
[0x404078] malloc@GLIBC_2.2.5 -> 0x7f0187ca50a0 (malloc) ◂— endbr64
[0x404080] setvbuf@GLIBC_2.2.5 -> 0x7f0187c815f0 (setvbuf) ◂— endbr64
[0x404088] getline@GLIBC_2.2.5 -> 0x7f0187c61db0 (getline) ◂— endbr64
[0x404090] exit@GLIBC_2.2.5 -> 0x401120 ◂— endbr64
```

Although most GOT entries point to `libc` address space, some point to the
binary itself. As a result, it is in fact possible to write into the GOT such
that the function loops itself, allowing us to call `main` (or an address within
`main`) once more and perform additional format string exploits.

> TODO
> 
> I'm unsure why some GOT entries are placed within the scope of the binary,
> would be worth researching for the write-up

A small blocker to this would be that there is no address pointing to the GOT
entry within the stack at the time we call. This is easily remedied however as
we can introduce such a pointer into the stack before the `printf` call is
performed. This could be done all in one call, but in my solve script, I opt to
write the address of the GOT entry I want to poison, `seccomp_release` in my
case, with two inputs. First using the prompt to read the replay file's hash,
then writing my format string payload in a second. With these steps, it's
required that the format string payload is shorter in length than that of the
first input, preventing an overwrite of the address we spent time to place into
the stack.

The following is what the stack looks like after each string is read, using big
endian for readability

After reading the "hash" of the replay

```
            ,-stack----------,
            |      ...       |
str_buf --> |aaaaaaaaaaaaaaaa|
            |aaaaaaaaaaaaaaaa|
            |aaaaaaaaaaaaaaaa|
            |aaaaaaaaaaaaaaaa|
            |aaaaaaaaaaaaaaaa|
            |aaaaaaaaaaaaaaaa|
            |aaaaaaaaaaaaaaaa|
            |aaaaaaaaaaaaaaaa|
            |      ...       |
            |aaaaaaaaaaaaaaaa|
            |aaaaaaaaaaaaaaaa|
            |aaaaaaaaaaaaaaaa|
        +---|0000000000404060|
        |   |      ...       |
        |   '----------------'
        |          ...
        |   ,-got------------,
        |   |      ...       |
        |   |00007f0187c707f0| --> printf @ libc
        +-->|00000000000401c0| --> seccomp_release thunk
            |00007f0187d98610| --> __memset_avx2_unaligned_erms @ libc
            |      ...       |
            '----------------'
```

After reading the "name" of the replay

```
            ,-stack----------,
            |      ...       |
str_buf --> | p a y l o a d  |
            | g o e s   h e r|
            | e : >aaaaaaaaaa|
            |aaaaaaaaaaaaaaaa|
            |aaaaaaaaaaaaaaaa|
            |aaaaaaaaaaaaaaaa|
            |aaaaaaaaaaaaaaaa|
            |aaaaaaaaaaaaaaaa|
            |      ...       |
            |aaaaaaaaaaaaaaaa|
            |aaaaaaaaaaaaaaaa|
            |aaaaaaaaaaaaaaaa|
        +---|0000000000404060|
        |   |      ...       |
        |   '----------------'
        |          ...
        |   ,-got------------,
        |   |      ...       |
        |   |00007f0187c707f0| --> printf @ libc
        +-->|00000000000401c0| --> seccomp_release thunk
            |00007f0187d98610| --> __memset_avx2_unaligned_erms @ libc
            |      ...       |
            '----------------'
```
