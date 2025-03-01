# overflow1

_written by `oblivious_turnip`_

solved by petiole

> The cyberteam has discovered some unauthorized access to the NYPD's
> infrastructure, we've matched the inbound IP addresses to Jake's botnet.
> After your previous success, we want you to see what you can find on these
> machines.
> 
> Additionally, take whatever you find with a grain of salt.

disclosure: i checked these challenge before release to ensure they were
solvable before the competition occurred. as a result, my solve likely took
longer than the allocated time within the competition. that being said, I did
not participate in the CTF at all

## about the program

it appears that the program is some authenticator, comparing usernames and
security codes to user input to determine who has access to the "NYPD Terminal".
insecurely, the developer of the program compiled the valid credentials of users
into the binary, which can be fetched either using `strings`, or retrieved by
looking at the `user_table_g` array in a decompiler like `ghidra`.

truncated strings output
```
_ITM_registerTMCloneTable
PTE1
H= A@
-- NYPD Terminal v1 --
1. Change username
2. Admin login
3. Exit
Username:
Enter security code:
cristina33
Intruder!
01843101
flag.txt
Failed to allocate memory for buffer, cannot proceed.
Only you can be trusted with this... %s
;*3$"
hoover95
7123308
runner86
7299126
kaylined        <- this is a username
5381272         <- this is a password
lenscroft12
7299126
GCC: (GNU) 14.2.1 20240805
GCC: (GNU) 14.2.1 20240910
chal.c
```

a user may be able to login with any of the username/security code pairs
seen below:

```
hoover95: 7123308
runner86: 7299126
kaylined: 5381272
lenscroft12: 7299126
```

additionally, the program allows authenticated users to change their username
(which is the name of the user at runtime), and attempt an "Admin login". in the
latter feature, the program attempts to check whether the user has been
authenticated as `cristina33: 01843101`. assuming the right credentials were
provided, then this prints out the flag, and exits

the issue faced here? we can never actually sign in as `cristina33`. in theory,
we can rename ourselves to be `cristina33`, but then we'll be missing their
security code. as such, we would be unable to log in

in theory, at least

## first solve - overwriting credentials

this exploit namely abuses the overflow caused by `strcpy` in
`change_username(char*)`.

the data required to store the user's username and security code are at most
`31` bytes each (based off the login function, which reads in `0x1f` bytes of
data). however, the `main` function stores both of these within a single buffer,
which will be referred to as the `creds_buf`. as a result, it would appear to be
like the following in memory:

```
main:creds_buf
+---------------+ -,
|               |  |
|   username    |  |
|     (32B)     |  |
|               |  |
+---------------+   } 72B in size
|               |  |
| security code |  |
|     (32B)     |  |
|               |  |
+---------------+ -`
```

after logging in, the `creds_buf` will look something like the following:

```
main:creds_buf
+user----+
|kaylined|
|        |
|        |
|        |
+pass----+
|5381272 |
|        |
|        |
|        |
+--------+
```

> of note: the blank spaces here represent unknown data or nullbytes. unknown
> data here is _most likely_ just nullbytes, but can be anything in theory.
> moving forward, there will always be a blank space after each string because
> it must end with a nullbyte

however, since the `fgets` call reads in 143 bytes, it is possible to write more
than just the username. this is particularly important, as the username is
updated by copying the new username into the `creds_buf` using `strcpy`, which
copies data without worrying about overflowing data.

that is, a payload of 33 `a`-s, which goes beyond the length of the username
section of the `creds_buf`, the updated `creds_buf` to the following:

```
main:creds_buf
+user----+
|aaaaaaaa|
|aaaaaaaa|
|aaaaaaaa|
|aaaaaaaa|
+code----+
|a 81272 |
|        |
|        |
|        |
+--------+
```

when attempting to run the `win` function, the administrative credentials are
compared using `strncmp`, comparing only the bytes of the name/code, and not
comparing the final nullbyte. therefore, a valid username match would be

```
main:creds_buf
+user----+
|cristina| <- matches `cristina33`
|33aaaaaa|
|aaaaaaaa|
|aaaaaaaa|
+code----+
|a 81272 |
|        |
|        |
|        |
+--------+
```

naturally, this would still fail since the security code is incorrect. however,
since we are able to continously write bytes

so, we write in the other security code as well

```
main:creds_buf
+user----+
|cristina| <- matches `cristina33`
|33aaaaaa|
|aaaaaaaa|
|aaaaaaaa|
+code----+
|01843101| <- matches `01843101`
|        |
|        |
|        |
+--------+
```

now that the right credentials are in the right place, we can just sign in
throught the admin login.

this has been written into the solve script, but a single-line bash line that
can be run to generate the payload is the following:

```sh
echo -e "kaylined\n5381272\n1\ncristina33aaaaaaaaaaaaaaaaaaaaaa01843101\n2" | ./overflow1
```

## second solve - shell access 

disclaimer: this is how I used Return Oriented Programming (ROP) to eventually
give me access to a `/bin/sh` process. this does get complicated, and I will not
be walking through it as I did for the data overwrite above.

although the `fgets` call does not overflow the local buffer made within the
function, the 72 byte buffer is passed by reference, and copied to it. as such,
the source buffer is being copied into a smaller destination buffer, allowing
the return address of `main` to be overwritten.

without PIE, and without stack canaries, the return address can just be
immediately overwritten. as such, a ROP chain can be generated (using
pwntools.ROP) to leak GOT entries, determining both what version of `libc` is
being used (based off page offsets) and where `libc` is loaded in memory.

as a result, using `plt.puts` to `puts` the `got.puts`, the location where
`libc` is loaded in memory can be resolved, and then a ROP chain off `libc` can
be executed such that `system("/bin/sh\0")` is run

then shell access (yippee)!
