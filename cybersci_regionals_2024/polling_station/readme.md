# Polling Station
### Challenge by Jason

> We are collecting polling data for the upcoming election.
> 
> Connect to the polling station with:
> 
>   nc 10.0.2.32 1337
> 
> The server will respond to a port for client connections. Clients can
> connect to the same IP on this port. Polling data will be received at the
> polling station.

_Disclaimer: I did not solve this challenge during CyberSci Regionals. I mostly
wanted to really study why the [provided solve
script](https://github.com/CyberSCI/PastChallenges/blob/3ef6e34f26c1ca7133c57fb530790e80cc165e1f/challenges/regionals-2024-25/pwn/polling_station/solve/exploit.py) actually worked._

```
$ ls
challenge.sh  Dockerfile  polling_station  xinetd.conf

$ pwn checksec ./polling_station
[*] '/home/user/files/polling_station'
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

The bulk of the challenge occurs within the `main()` function, which has been
decompiled and annotated below

```c
void main(void)

{
  int sa_svr;
  ssize_t sVar1;
  int d_size;
  char *pcVar2;
  int d_iter0;
  int d_iter1;
  int d_iter2;

                    /* set up listening socket */
  sa_svr = init();
  do {
    poll(fds,0xb,30000);
    for (d_iter0 = 1; d_iter0 < 0xb; d_iter0 = d_iter0 + 1) {
      if (fds[d_iter0].revents != 0) {
                    /* controllable buffer size based off `read`
                       
                       this also does not need to be overwritten if nullbytes are read in :> */
        sVar1 = read(fds[d_iter0].fd,buf,0x1000);
        d_size = (int)sVar1;
        poll_results[d_iter0 + -1].length = d_size;
                    /* controllable malloc size, up to 0x1000 bytes */
        pcVar2 = (char *)malloc((long)(d_size + 1));
        poll_results[d_iter0 + -1].name = pcVar2;
        strlcpy(poll_results[d_iter0 + -1].name,buf,(long)d_size);
        close(fds[d_iter0].fd);
        fds[d_iter0].fd = -1;
      }
    }
                    /* if something happened on the server socket */
    if (fds[0].revents != 0) {
      for (d_iter1 = 1; d_iter1 < 0xb; d_iter1 = d_iter1 + 1) {
                    /* seek for an index that contains a blank entry */
        if (fds[d_iter1].fd < 0) {
          d_size = accept(sa_svr,(sockaddr *)0x0,(socklen_t *)0x0);
          fds[d_iter1].fd = d_size;
                    /* Bit  Value   Set/Unset   Common Flag (if any)
                       0    0x001   Unset       POLLIN
                       2    0x004   Unset       POLLOUT
                       8    0x100   Unset       POLLERR/POLLHUP/POLLRDHUP (platform dependent)
                       Others       Set         All others
                       
                       thanks chatgpt */
          fds[d_iter1].events = -0x105;
          write(fds[d_iter1].fd,"Who will you be voting for?\n",0x1c);
          break;
        }
      }
    }
    for (d_iter2 = 0; d_iter2 < 10; d_iter2 = d_iter2 + 1) {
      if (poll_results[d_iter2].name != (char *)0x0) {
        printf("Response received: ");
        fwrite(poll_results[d_iter2].name,1,(long)poll_results[d_iter2].length,stdout);
        putchar(10);
        fflush(stdout);
        free(poll_results[d_iter2].name);
                    // no uaf :(
        poll_results[d_iter2].name = (char *)0x0;
      }
    }
  } while( true );
}
```

Note that the only other developer defined function here is `init()`, which sets
up a server socket, along with 11 `struct pollfd` structures (see `poll(3p)`),
one for the server socket itself, and 10 others for secondary connections.

When an initial connection is made, the binary opens another random port,
where secondary connections are accepted and added to the global `fds` array for
interfacing. It is important to note that `stdout` of the binary will be written
to the socket where the initial connection was made, and reads from/writes to the
secondary sockets are made to the file descriptors returned from `accept`.

Each secondary connection uses is then presented with the text "Who will you be
voting for?", before waiting for user-input. The name is written into memory
using `read(3p)` into a global buffer, which is then copied using
`strlcpy(3bsd)` into a `poll_result` structure, which I have defined as the
following.

```c
typedef struct _poll_result {
    int length;
    undefined4 ???;
    char * name;
} poll_result;
```

Here, the `name` is stored within a heap chunk created by `malloc(3)`, where the
size of the chunk is one more than the integer representation of the number of
bytes read, returned from `read`

```c
        sVar1 = read(fds[d_iter0].fd,buf,0x1000);
        d_size = (int)sVar1;
        poll_results[d_iter0 + -1].length = d_size;
                    /* controllable malloc size, up to 0x1000 bytes */
        pcVar2 = (char *)malloc((long)(d_size + 1));
        poll_results[d_iter0 + -1].name = pcVar2;
        strlcpy(poll_results[d_iter0 + -1].name,buf,(long)d_size);
```

The binary uses `poll(3p)`, which handles IO events between the set of file
descriptors, stored in `fds`. This ultimately determines which file descriptors
have changes made to them, and allows the binary to selectively read from each
file descriptor without unnecessarily blocking. That is, only read from a file
descriptor if and only if it has data buffered in it.

In this particular example, the `revents` flags are read here to determine if
anything has happened to the socket.

```c
  do {
    poll(fds,0xb,30000);
    for (d_iter0 = 1; d_iter0 < 0xb; d_iter0 = d_iter0 + 1) {
      if (fds[d_iter0].revents != 0) {
```

Interestingly, the binary appears to be good at cleaning up allocated chunks
when they are no longer necessary, unlike other heap challenges I've seen
(which, admittedly, is few).

```c
    for (d_iter2 = 0; d_iter2 < 10; d_iter2 = d_iter2 + 1) {
      if (poll_results[d_iter2].name != (char *)0x0) {
        printf("Response received: ");
        fwrite(poll_results[d_iter2].name,1,(long)poll_results[d_iter2].length,stdout);
        putchar(10);
        fflush(stdout);
        free(poll_results[d_iter2].name);
                    // no uaf :(
        poll_results[d_iter2].name = (char *)0x0;
      }
    }
```

This, however, is still a heap challenge, which leverages some more easily
overlooked bugs.

## vulnerabilities

Most vulnerabilities stem from the use of `read(3p)`, alongside its unchecked
output in combination with the other functions used throughout the binary,
namely `strlcpy(3bsd)` and `fwrite(3)`. One other vulnerability stems from the
misconfiguration of `poll(3p)`, where all flags but `POLLIN`, `POLLOUT` and
`POLLERR/POLLHUP/POLLRDHUP` are set. The flags set allow a socket to send
[out-of-band
data](https://www.gnu.org/software/libc/manual/html_node/Out_002dof_002dBand-Data.html),
which automatically causes `poll` to exit, but `read` to expect input, hanging
the process in a controllable manner.

That is:

| Address       | Description of Vulnerability  |
|--:            |:--                            |
| `0x00401702`  | Misconfiguration of events, allowing any type of message to be detected despite not being checked by the binary itself |
| `0x004015c2`  | No error checking from `read`, causing `-1` to be interpreted as the length of the input. In this circumstance, `fwrite` and `strlcpy` can be called with arguments of `0xffff_ffff_ffff_ffff`, and `malloc` may be called with an argument of zero, allowing for out-of-bounds reads and writes |
| `0x004015c2`  | Discrepancy input read by `read` and "name" written by `strlcpy`, which stems from `strlcpy`'s unwillingness to copy more than one nullbyte. This can allocate buffers of specific sizes without destroying most of any existing metadata, enabling out-of-bound reads with finer control of the length |

## exploitation

In all, the exploit shapes the heap such that a heap address can be exposed,
along with an addresses within `libc`. The libc version of `GLIBC 2.39`
indicates that
[Safe-Linking](https://theb4tmite.github.io/posts/heap-safe-linking/) is used,
the heap address can be used to generate the heap security key, which can be
used with the address of `libc` to set up a [tcache
poison](https://github.com/shellphish/how2heap/blob/master/glibc_2.39/tcache_poisoning.c),
which enables a [GOT](https://en.wikipedia.org/wiki/Global_Offset_Table)
overwrite, forcing an imported function to point at `system`, where
`system("/bin/sh")` can be setup and called.

### heap leak

#### goal

[Leaks](https://media.tenor.com/XjWq1YsrqOQAAAAM/hatsune-miku.gif) can be
achieved using one of the two out-of-bound reads mentioned above. In my exploit
script, I use the second one, which differs from Jason's original solution. As
`read(3p)` accepts null bytes as input, and `strlcpy(3bsd)` stops writing at the
first null byte it sees, I can reallocate previously-freed chunks, exposing any
chunk metadata left behind. This is not perfect, however, as `strlcpy` does
write the first null byte it sees, but this is fairly manageable.

As mentioned earlier, we want to get both an address to `libc` and the heap
security key, which can be derived from a leaked heap address.

To achieve this, the following can be done:

1. Create seven chunks, two of them of the same size next to each other in
   preparation for a tcache-poison
2. Create one large chunk, I've made mine `0x400` bytes in size
3. Create one additional chunk to keep the large chunk from merging with
   wilderness
4. free all of them, in order of creation

This would place the large chunk in the unsorted bin, which is a doubly linked
list where the freed chunk has a forward and backward pointer to the head of the
unsorted bin. This is extremely useful as the head of the unsorted bin is stored
as a global variable in `libc`, which can then be used to reliably calculate
where `libc` is loaded in memory.

```
    |                   |
 +--| unsorted bin head |<-+-+
 |  |                   |  | |
 |  +-libc--------------+  | |
 |  |                   |  | |
 |                         | |
 |   ...                   | |
 |                         | |
 |  |                   |  | |
 |  +-heap--------------+  | |
 |  |                   |  | |
 +--->+freed chunk----+ |  | |
    | |      fp       | |--+ |
    | |      bp       | |----+
    | +---------------+ |
```

#### blocker and solution

***The biggest issue is***, chunks are effectively immediately freed after they
are used, and only created when input is read. As such, it is extremely
difficult to create, and subsequently free, two chunks on the heap in a row. Not
only would creating 9 chunks be near impossible, creating them in a predictable
order would be likely be actually impossible. As a result, the events
misconfiguration can be abused.

For exception control, TCP packets (appear to have, since I am not knowledgable
about this) a packet flag labelling packets as
[out-of-band](https://www.gnu.org/software/libc/manual/html_node/Out_002dof_002dBand-Data.html).
Ignoring their practical use (since I am largely unfamiliar with them), they are
extremely useful here as out-of-band packets can indicate to `poll` that a
packet is "ready", and `poll` no longer needs to wait for data. As such, `poll`
returns, allowing code flow to advance to the call to `read`. Interestingly, the 
out-of-band data is not read in, and the program simply blocks until a read is
captured. This gives us time to actually set up the necessary requests, in
order, to create the remainder of the chunks. Once everything has been set up,
the socket hanging the process can have actual data sent to it, causing the read
to resolve.

In all:

1. Create all sockets necessary

```py
    ## setup a socket to block the connection
    fds[1] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    fds[1].connect((HOST, poll_port))
    sleep(1)
    ## setup buffers as needed
    for i in range(9):
        fds[i+2] = remote(HOST, poll_port)
        sleep(1)
```

2. Send one packet with out-of-band data, causing the program to hang

```py
    ## block the free loop to set up multiple writes
    fds[1].send(b'\0', socket.MSG_OOB)
```

3. On the remaining sockets, create requests for all necessary chunks

```py
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
```

4. Send a bit of data on the hanging socket, which causes the process to resume

```
    fds[1].send(b'\0')
    fds[1].close()
    sleep(1)
```

By this point, the program will return to `poll`, and notice that all the
sockets have data ready, allocate all chunks, and subsequently frees all of them

#### actually leaking addresses

There are two main ways to get the leaks we're looking for, using one of the two
out-of-bound reads from earlier. In Jason's solve script, he prematurely closes
the socket such that `read` returns `-1`, and `fwrite` prints
`0xffff_ffff_ffff_ffff` bytes.

In my exploit script, I opt to leak addresses by reallocating chunks, and read
more chunks than I wrote. This is possible as the number of bytes written to
`stdout` by `fwrite` is correlated to the number of bytes read in, but the number

### tcache poison

### GOT overwrite and shell
