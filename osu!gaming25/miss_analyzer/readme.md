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

Luckily, the data format that the binary is expecting to parse is a subset of
the data formats specified on [OSU's well documented
wiki](https://osu.ppy.sh/wiki/en/Client/File_formats/osr_%28file_format%29).
This shows that the data contained within the file is expected to be written in
a specific order, following both fixed and variable data sizes.

Using Binary Ninja ([\*_cough_\*](https://youtu.be/j69knNADinw)), we can look at
the implementation of each of these parsers, starting at the most basic and
move our way up.

### Byte parser

![](screenshots/read_byte_decomp_binja.png)



Each of these data points are printed to the terminal immediately after parsing
that part of the file.

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
blocking an immediate write to a return address. However, as the binary is
position _dependent_ and has Partial RELRO. This means that there may be a GOT
entry that we could abuse to start playing around with

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

These GOT entries are _lazily linked_, which entails that the binary will
attempt to resolve their addresses at runtime when the function is being called.
This was a common compiler option as it improved the time to start up a given
binary. The binary only needed to resolve addresses at the moment the desired
function is called, thus, GOT entries can point to code which resolves each
entry stored within the binary itself. Once determined, the GOT can be updated
to point to the desired function in `libc`.

Lazily linked GOT entries, however, require a _writable_ memory allocation at
runtime, leading it vulnerable to manipulation. In our case, we can abuse an
unsresolved GOT entry to point back within the binary (especially since we know
its exact address with the binary being position-dependent) and launch the main
function a second time. This means we can resolve an address in `libc` the first
time we abuse the `printf` vulnerability, and abuse it too.

From the entries above, it is seen that most GOT entries have been resolved to
their `libc` addresses. However, there are some unresolved entries, namely the
following:

- `free@GLIBC_2.2.5`
- `putchar@GLIBC_2.2.5`
- `__stack_chk_fail@GLIBC_2.2.5`
- `seccomp_release@GLIBC_2.2.5`
- `exit@GLIBC_2.2.5`

> References I found useful related to lazy linking
>
> - [Lecture Notes: Basics of the Global Offset Table](https://cs4401.walls.ninja/notes/lecture/basics_global_offset_table.html)
> - [Why does gcc link with '-z now' by default, although lazy binding is the default for ld?](https://stackoverflow.com/a/65277554)
> - [RELocation: Read-Only](https://hockeyinjune.medium.com/relro-relocation-read-only-c8d0933faef3)
>
> tldr, _this_ is the reason why relocation tables are writable - to improve
> binary startup performance. However, modern compilers typically opt to resolve
> address entries _immediately at load_ and ensure the GOT is read-only

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
            ,-stack----------,     ,  ...   ,
            |      ...       |     |........|
str_buf --> |7061796c6f616420|     |payload |
            |676f657320686572|     |goes her|
            |653a3eaaaaaaaaaa|     |e :>....|
            |aaaaaaaaaaaaaaaa|     |........|
            |aaaaaaaaaaaaaaaa|     `  ...   `
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

This means, the name of the replay can be specified
