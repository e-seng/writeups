# overflow2

_written by `oblivious_turnip`_

solved by petiole

> After you hacked the first terminal, it appears that you triggered a deadman's
> switch, spawning a new "admin" NYPD terminal. We need you to break into this
> terminal and find out what it contains.
> 
> Additionally, it is prudent of me to inform you that Jake is a pathological
> liar. And everything he says should not be trusted. After all, it is in a
> criminals's nature.

disclosure: i checked these challenge before release to ensure they were
solvable before the competition occurred. as a result, my solve likely took
longer than the allocated time within the competition. that being said, I did
not participate in the CTF at all

## about the program

as indicated by the description, the application is terminal application that
enables users to connect and access suspect data. here, any suspect data is
stored as global data, `suspect_table_g`.

there are also another two global values used throughout the program, namely
`g_edit_buffer` and `g_format`. these two global values are defined as character
pointers, each assigned a value using `malloc` close to the start of the `main`
function.

```c

undefined8 main(void)

{
  // ... (truncated)
  g_edit_buffer = (char *)malloc(0x30);
  if (g_edit_buffer == (char *)0x0) {
    puts("Couldn\'t allocate memory for g_edit_buffer, contact the CTF devs.");
                    /* WARNING: Subroutine does not return */
    exit(3);
  }
  g_format = (char *)malloc(0x30);
  if (g_format == (char *)0x0) {
    puts("Couldn\'t allocate memory for g_format, contact the CTF devs.");
                    /* WARNING: Subroutine does not return */
    exit(3);
  }
  strncpy(g_edit_buffer,"ZG9feW91X2V2ZW5faGF2ZV9hbnlfcHJvb2Y/",0x30);
  strncpy(g_format,"Changed %s to %s.",0x30);
  // ... (truncated)
```

> note that this, and all future decompilations, have been generated using
> `ghidra`

as these calls to `malloc` occur right at the start of the program execution,
thus memory fragmentation would not yet be possible, both of these buffers are
defined one right after the other.

```
globals        : heap
               :
g_edit_buffer ---+   +--------+
g_format ----+ : +-> |ZG9feW91|
             | :     |X2V2ZW5f|
             | :     |aGF2Zv9h|
             | :     |bnlfcHJv|
             | :     |b2Y/    |
             | :     |        |
             | :     +--------+
             +-----> |Changed |
               :     |%s to %s|
               :     |.       |
               :     |        |
               :     |        |
               :     |        |
               :     +--------+
```

as their names may suggest, `g_format` is used as a format string specifier for
a printf call within a call to `printf` in `edit_user(char*, int)`. similarly,
`g_edit_buffer`, is used to hold user input as they enter it using a `fgets`
call. this may be done in order to prevent a stack-based overflow, where control
flow can definitely be affected.

```c
void edit_user(char *param_1,int param_2)

{
  char *pcVar1;
  char local_38 [48];
  
  pcVar1 = param_1;
  if (param_2 != 0) {
    pcVar1 = param_1 + 0x30;
  }
  strncpy(g_edit_buffer,pcVar1,0x30);
  pcVar1 = param_1;
  if (param_2 != 0) {
    pcVar1 = param_1 + 0x30;
  }
  strncpy(local_38,pcVar1,0x30);
  printf("Enter in new value: ");
  fgets(g_edit_buffer,0x240,stdin);
  printf(g_format,local_38,g_edit_buffer);
  if (param_2 != 0) {
    param_1 = param_1 + 0x30;
  }
  strncpy(param_1,g_edit_buffer,0x30);
  return;
}
```

also of note, the challenge's flag (or one of them, at least) has been written
into the stack of `vuln`, but is otherwise never referenced or read anywhere
throughout the program.

## point of overflow

`edit_user` has an overflow within the heap, written into `g_edit_buffer` by
`fgets` due to the huge input size. although not on the stack, which would
immediately give a malicious user to control the execution flow by overwriting
the return address, the overflow is able to affect data within the heap. this
namely affects the two character arrays seen above, due to their placements.
that is, because `g_format` was `malloc`'d after `g_edit_buffer`, then
`g_format` has a higher address than `g_edit_buffer`. as such, when writing
strings into `g_edit_buffer`, each character is written in order, ascending in
addresses.

```
globals        : heap
               :
g_edit_buffer ---+   +--------+
g_format ----+ : +-> |ZG9feW91|
             | :     |X2V2ZW5f|
             | :     |aGF2Zv9h|
             | :     |bnlfcHJv|
             | :     |b2Y/    |
             | :     |        |
             | :     +--------+
             +-----> |Changed |
               :     |%s to %s|
               :     |.       |
               :     |        |
               :     |        |
               :     |        |
               :     +--------+
```

writing 49 `z` characters to `g_edit_buffer`, for example, results in the
following

```
globals        : heap
               :
g_edit_buffer ---+   +--------+
g_format ----+ : +-> |zzzzzzzz|
             | :     |zzzzzzzz|
             | :     |zzzzzzzz|
             | :     |zzzzzzzz|
             | :     |zzzzzzzz|
             | :     |zzzzzzzz|
             | :     +--------+
             +-----> |z anged |
               :     |%s to %s|
               :     |.       |
               :     |        |
               :     |        |
               :     |        |
               :     +--------+
```

again, this does not directly do much on its own. however, it is important to
recall that `g_format` is used by `printf` as its format string specifier. any
computer science/software engineering professor may remind you (or mines did, at
least), that user-controllable buffers should not be used as format format
string specifiers. this is namely because this can allow for a lot of control
over data, including the data stored on the stack.

further details about format string exploits can be found
[here](https://cs155.stanford.edu/papers/formatstring-1.2.pdf). in summary,
`printf` uses variable arguments to allow developers to specify any number of
arguments to pass into the function call. with only 6 argument registers (one
being used to specify the string format specifier), and the possibility that
additional arguments may be supplied by developers, `printf` can read arguments
from the stack

```c
printf(s_fmt, // rdi
       $rsi,
       $rdx,
       $rcx,
       $r8,
       $r9,
       ($rsp+0),
       ($rsp+1),
       ...
       );
```

## solve 1 - stack leak

as the actual string data of the flag can be found on the stack, there can be a
format string that can be generated such that its bytes can be dumped, though it
requires further analysis

at the time of abusable `printf` call, the stack appears like the following

```
+edit_user---------------+ -,
|                        |  |
| <locals>               |   } 64B
|                        |  |
+------------------------+ -;
| base address           |   } 8B
+------------------------+ -;
| return address         |   } 8B
+vuln--------------------+ -;
| <locals, 16B>          |  |
| +s_flag------+ -,      |  |
| | <bytes of  |  |      |  |
| |  the flag> |   } 64B |   } 96B
| |            |  |      |  |
| +------------+ -`      |  |
|                        |  |
+------------------------+ -;
| base address           |   } 8B
+------------------------+ -;
| return address         |   } 8B
+main--------------------+ -;
| base address           |   } 8B
+------------------------+ -;
| return address         |   } 8B
+more stack...-----------+ -;
|                        |  |
           ...
```

using `pwndbg`'s `tel` command, the stack dump can be seen

```
pwndbg> tel 40
00:0000│ rsp     0x7ffea8405150 ◂— 0x100000001
01:0008│-038     0x7ffea8405158 —▸ 0x5990a8863020 (suspect_table_g) ◂— 'Harriette Explo'
02:0010│ rcx rsi 0x7ffea8405160 ◂— '48e6b718e2672d'
03:0018│-028     0x7ffea8405168 ◂— 0x643237363265 /* 'e2672d' */
04:0020│-020     0x7ffea8405170 ◂— 0
... ↓            3 skipped
08:0040│ rbp     0x7ffea8405190 —▸ 0x7ffea8405200 —▸ 0x7ffea8405210 —▸ 0x7ffea84052b0 —▸ 0x7ffea8405310 ◂— ...
09:0048│+008     0x7ffea8405198 —▸ 0x5990a886060f (vuln+374) ◂— jmp vuln+84
0a:0050│+010     0x7ffea84051a0 ◂— 2
0b:0058│+018     0x7ffea84051a8 ◂— 0x200000001
0c:0060│+020     0x7ffea84051b0 ◂— 'test{flag}\n'
0d:0068│+028     0x7ffea84051b8 ◂— 0xa7d67 /* 'g}\n' */
0e:0070│+030     0x7ffea84051c0 ◂— 0
... ↓            5 skipped
```

as `printf` can read values from the stack, then it is possible for a new
string formatter to be generated to leak all data on the stack related to the
unused flag.

> it is important to note that `%s` cannot be used here, as the formatter
> expects a pointer. as the bytes on the stack are the exact bytes of the flag,
> it is highly likely that the bytes do not form a valid pointer. therefore,
> using `%s` would lead the program to segmentation fault, nothing more

to read the entire 16B chunk of data, `%p` or `%llx` (a pointer specifier, or a
long long hex specifier, both datatypes being 16 bytes in size) can be used.
this can be used in conjunction with a format specifier, generating the
following payload:

```py
b"%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p`%p%p%p%p%p%p%p%p"
# ^                                  ^ 
# |                                  ` dumping 8 16-byte chunks of data
# ` offset until the right "argument" is selected (17 arguments), which removes
#   first 5 arguments from the registers, and removes the next 12 items from the
#   stack
```

the size of this can be reduced by using offset specifiers

```py
b"%18$p%19$p%20$p%21$p%22$p%23$p%24$p%25$p"
```

at this point, this gives the _hexadecimal_ of the data on the stack. as a
result, each value needs to be converted from hex, back into bytes before the
string can be restored

```py
for hex_chunk in flag_leak.split(b'0x'):
    if not hex_chunk: continue
    io.debug(f"converting {hex_chunk}")
    raw_chunk = int(hex_chunk, 16)
    flag += pack(raw_chunk, "all")
```

this gives `magpieCTF{h3@p_0r_b8ff3r_0v3rfL0w}`

## solve 2 - shell access

looking at the man-pages of `printf`, it can be seen that there exists a format
specifier, which is _actually able to perform writes_

```
n   The number of characters written so far is stored into the integer pointed
    to by the corresponding argument. That argument shall be an int *, or
    variant whose size matches the (optionally) supplied integer length
    modifier. No argument is converted. (This specifier is not supported by the
    bionic C library.) The behavior is undefined if the conversion specification
    includes any flags, a field width, or a precision.
```

as `%n` would link itself to a pointer within the range of arguments, that being
either regsiters or within the stack, there requires some addtional work before
arbitrary data can just be written to the stack. much like `%s`, a payload
cannot _just_ write `%n` such that data is written at that location, but would
need to use another pointer on the stack, which would point to the desired
location

where can we get so many stack pointers? well, in `x86-64`, a _stack frame_ is
structured like the following:

```
+----------------+
| locals         |
|                |
|                |
+----------------+
| base address   |
+----------------+
| return address |
+----------------+
```

the base address here denotes where the bottom of the next stack frame is, such
that the `leave` instruction works properly. therefore, with enough function
call nesting, there exists a series of addresses on the stack, all pointing
to one another, each pointing lower into the stack. this looks like the
following

```
   +-----------+
   |           |    <- rsp
   |           |
   +-----------+
+--| base addr |    <- rbp
|  +-----------+
|  | ret addr  |
|  +-----------+
|  |           |
|  |           |
|  +-----------+
+->| base addr |--+
   +-----------+  |
   | ret addr  |  |
   +-----------+  |
   |           |  |
   |           |  |
   +-----------+  |
+--| base addr |<-+
|  +-----------+
|  | ret addr  |
|  +-----------+
|  |           |
|  |           |
|  +-----------+
+->| base addr |--+
   +-----------+  |
   | ret addr  |  |
   +-----------+  |
```

therefore, it is possible to use a base pointer, to overwrite _another_ base
pointer, which then can be used to write to that address.

in steps:

```
1.    +-----------+                 2.    +-----------+                        3.   +-----------+   
      |           |                       |           |                             |           |
      |           |                       |           |                             |           |
      +-----------+                       +-----------+                             +-----------+
   +--| base addr |<- align %n here    +--| base addr |                          +--| base addr |
   |  +-----------+                    |  +-----------+                          |  +-----------+
   |  | ret addr  |                    |  | ret addr  |                          |  | ret addr  |
   |  +-----------+                    |  +-----------+                          |  +-----------+
   |  |           |                    |  |           |                          |  |           |
   |  |           |                    |  |           |                          |  |           |
   |  +-----------+                    |  +-----------+                          |  +-----------+
   +->| base addr |--+ <- to write     +->| base addr |--+ <- update base addr   +->| base addr |--+ <- align %n here
      +-----------+  |    data here       +-----------+  |                          +-----------+  |
      | ret addr  |  |                    | ret addr  |<-+                          | yippeeeee |<-+ <- to write
      +-----------+  |                    +-----------+                             +-----------+       data here
      |           |  |                    |           |                             |           |
      |           |  |                    |           |                             |           |
      +-----------+  |                    +-----------+                             +-----------+
   +--| base addr |<-+                 +--| base addr |                          +--| base addr |
   |  +-----------+                    |  +-----------+                          |  +-----------+
   |  | ret addr  |                    |  | ret addr  |                          |  | ret addr  |
   |  +-----------+                    |  +-----------+                          |  +-----------+
   |  |           |                    |  |           |                          |  |           |
   |  |           |                    |  |           |                          |  |           |
   |  +-----------+                    |  +-----------+                          |  +-----------+
   +->| base addr |--+                 +->| base addr |--+                       +->| base addr |--+
      +-----------+  |                    +-----------+  |                          +-----------+  |
      | ret addr  |  |                    | ret addr  |  |                          | ret addr  |  |
      +-----------+  |                    +-----------+  |                          +-----------+  |
```

__however__, this is partically incomplete, as addresses are typically comprised
of 6 bytes, which gets _really large, really quickly_. recall that this number
of bytes needs to be written in order for `%n` to write that value there. so,
instead of writing upwards to 2.8e14 characters, it is instead quicker to write
out the address in short-sized chunks, each using `%hn` instead

that is, split a typical quad-word into a series of half-words, and write each
half-word individually. in total, this takes more requests, but is actually
possible to print out the number of characters to represent a full address

ie.

```
|                 64 bits, storing some data                     |
.                                                                .
:                                                                 \
`                                                                  `
| 16 bit part    | 16 bit part    | 16 bit part    | 16 bit part    |
```

looking at the memory of this program specfically, the following stack can be
seen at the `printf` call

```
+edit_user---------------+ -,
|                        |  |
| <locals>               |   } 64B
|                        |  |
+------------------------+ -;
| base address           |   } 8B
+------------------------+ -;
| return address         |   } 8B
+vuln--------------------+ -;
| <locals, 16B>          |  |
| +s_flag------+ -,      |  |
| | <bytes of  |  |      |  |
| |  the flag> |   } 64B |   } 96B
| |            |  |      |  |
| +------------+ -`      |  |
|                        |  |
+------------------------+ -;
| base address           |   } 8B
+------------------------+ -;
| return address         |   } 8B
+main--------------------+ -;
| base address           |   } 8B
+------------------------+ -;
| return address         |   } 8B
+more stack...-----------+ -;
|                        |  |
           ...
```

as a result, it is possible to abuse the multiple base addresses on the stack in
order to write arbitrary data into memory, as long as the write occurs to the
8th address down the stack (assuming the address pointed to by `rsp` is index
zero, or the 13th overall argument of the `printf` function call.

this, unfortunately, is not the end of the process, however. unlike above, where
offset specifiers were used to shorten the payload string, each individual
argument must have an associated format specifier.

that is, writing `0x7ff` characters out, then using something like `%$13hn` would
_not_ result in writing `0x7ff` to the next base address. it, instead, performs
absolutely no write whatsoever. no idea why, possibly becuase it resolves
format-specified arguments first? not sure, would be cool to look into, but
probably later. as a result, each argument must be associated to some format
specifier.

this causes some issues, for the two core reasons

1. memory and registers typically contain random or inconsistent values,
   especially when exploring other stack frames
2. format string specifiers are made to print stuff. as a result, whatever is in
   that register or address of memory can appear differently at runtime

these two reasons makes it difficult to perform arbitrary data writes, as `%n`
specifically _writes the number of bytes written up to that point_.

however, there are a few format specifiers that can be used such that the number
of characters being printed, and thus the value that the `%n` specifier will
write, is predictable. the easiest option is `%c`, which is the format specifier
to write a single character. this means that no matter the value at the address,
the value will be casted into a single-byte character, and printed accordingly.

> note, this _does not change_ the number of arguments necessary, as although a
> character is aligned to a single byte, each argument is still assumed to be
> aligned to a double word

with this, the number of characters written out can also be controlled by
using additional format specifiers. specifically, writing some value `<val>`
into the specifier in the following way, `%<val>c`, will ensure that the
specifier prints specifically `<val>` number of bytes.

therefore, to write to the address that's being pointed to, the following
payload can be used to write `0x7ff` to the address pointed to by the base
address.

```c
"%c%c%c%c%c%c%c%c%c%c%c%2036c%hhn"
// note, 2036 is actually 0x7f4. however, the 11 additional characters being
// written by the first 11 specifiers ensures that 0x7ff characters are printed,
// and, in turn, 0x7ff is written
```

right now, though, this only modifies the base address of the next stack frame.
using an example:

```
                +-----------+ .
0x7fff 1000     |           |  |
                     ...        } 48 bytes
                |           |  |
                +-----------+ `
0x7fff 1030  +--|0x7fff 1098|
             |  +-----------+
0x7fff 1038  |  | ret addr  |-----> some instruction
             |  +-----------+ .
             |  |           |  |
             |       ...        } 96 bytes
             |  |           |  |
             |  +-----------+ `
0x7fff 1098  +->|0x7fff 10b8|--+
                +-----------+  |
0x7fff 10a0     | ret addr  |--+--> some instruction
                +-----------+  Y
                ... down to the specified address
```

using the payload above, the stack will be updated to look like the following
once completing the `%hhn` format specifier, will look like the following:

```
                ... up to the specified address
                +-----------+  |
0x7fff 1000     |           |  |
                     ...       |
                |           |  |
                +-----------+  |
0x7fff 1030  +--|0x7fff 1098|  |
             |  +-----------+  ^
0x7fff 1038  |  | ret addr  |--+--> some instruction
             |  +-----------+  |
             |  |           |  |
             |       ...       |
             |  |           |  |
             |  +-----------+  |
0x7fff 1098  +->|0x7fff 07ff|--+
                +-----------+
0x7fff 10a0     | ret addr  |-----> some instruction
                +-----------+
```

this doesn't immediately give the write that we wanted, but, because the base
address is already pointing to someplace on the stack, we can use a single write
to update it, and point to where we actually want to write to. in the running
example, the short `0x1030` can be used to point to the return address. this
looks like:

```
                +-----------+ .                                             +-----------+
0x7fff 1000     |           |  |                            0x7fff 1000     |           |
                     ...        } 48 bytes                                       ...
                |           |  |                                            |           |
                +-----------+ `                                             +-----------+
0x7fff 1030  +--|0x7fff 1098|                               0x7fff 1030  +--|0x7fff 1098|
             |  +-----------+                                            |  +-----------+
0x7fff 1038  |  | ret addr  |-----> some instruction        0x7fff 1038  |  | ret addr  |<-+ --> some random data
             |  +-----------+ .                                          |  +-----------+  |
             |  |           |  |                                         |  |           |  |
             |       ...        } 96 bytes                               |       ...       |
             |  |           |  |                                         |  |           |  |
             |  +-----------+ `                                          |  +-----------+  |
0x7fff 1098  +->|0x7fff 10b8|--+                            0x7fff 1098  +->|0x7fff 1030|--+
                +-----------+  |                                            +-----------+
0x7fff 10a0     | ret addr  |--+--> some instruction        0x7fff 10a0     | ret addr  |-----> some instruction
                +-----------+  Y                                            +-----------+
                ... down to the specified address
```

now, we can use _this new address_ to write the desired arbitrary data. this can
be done in a few ways in this circumstance, since the `printf` call occurs
within a loop. using this loop, it is possible to then reference the controlled
base address we updated to write to the return address. this is also only true
because the base address is never updated again as the function owning the stack
frame never returns. the second method is a lot simpler, however.

it is actually possible to continue to payload from before to perform both
desired writes. that is, the update to the controlled base address and the write
to the desired location can occur within a single `printf` call. this just
requires more format specifiers until the right argument is selected, very
similar to before.

something to keep in mind, however, `%n` will print the __total__ number of
characters written. as a result, the characters written for the previous
`printf` payload needs to be counted as well. if necessary, the count of
characters written can be overflowed to write the desired value. in a more
mathematical form, assuming that a `short` is being written. otherwise, a single
byte would bitwise OR with `0x100` instead of `0x10000`

```
characters to write = ((desired value) | 0x10000) - (previous character count)
```

therefore, writing `0x0000`, now at the example stack above, will have the
following payload

```c
"%c%c%c%c%c%c%c%c%c%c%c%4133%hhn%c%c%c%c%c%c%c%c%c%c%61382c%hhn"
//                           ^                       ^      ^
//                           |                       |      ` write to the return address
//                           |                       ` writing 0xefc6, where 0x1030 + 0xefd0 + 10 = 0x10000
//                           ` update the base address, writing 0x1030 characters in all
```

this results in the following stack

```
                +-----------+
0x7fff 1000     |           |
                     ...
                |           |
                +-----------+
0x7fff 1030  +--|0x7fff 1098|
             |  +-----------+
0x7fff 1038  |  |0x???? 0000|<-+ --> some desired data
             |  +-----------+  |
             |  |           |  |
             |       ...       |
             |  |           |  |
             |  +-----------+  |
0x7fff 1098  +->|0x7fff 1030|--+
                +-----------+
0x7fff 10a0     | ret addr  |-----> some instruction
                +-----------+
```

this is limited, however, only two bytes are being written at a time. in this
case, we are lucky since the `printf` call would be repeated. in other cases, it
may be necessary to also overwrite the return address of the current stack frame
to call `printf` again, but that will not be covered in this writeup

as codeflow will now return to the `printf` call, different format string
payloads can be used. it is important to note that the number of bytes being
written, that being the sizeof the data type being referened, should be added
per call to point to the right offset of off the data.

that is:

```
0x07ff 3210     | 16 bit part    | 16 bit part    | 16 bit part    | 16 bit part    |
                 ^                ^                ^                ^
1.               |                |                |                ` write to offset 0 (0x07ff3210)
2.               |                |                ` write to offset 2 (0x07ff3212)
3.               |                ` write to offset 4 (0x07ff3214)
4.               ` write to offset 6 (0x07ff3216)
```

from here, it is then possible to create a ROP chain that can spawn a shell,
since it is now possible to write arbitrary bytes to the stack. For more
information on ROP chains, I'll try to go into more details in my ROP writeup

that being said, now that we have a shell, a new flag can be submitted
`magpieCTF{s3c0nd_3ntr@nc3}`
