# overflow2

_written by `oblivious_turnip`_

solved by petiole

> New email from cors@nypd.gov:
> 
> We've identified some infected routers belonging to a botnet, ran by the
> hacker named "Jake Kaylined" (known aliases "netrunner", "kaylined")
> coincidentally, one of our prime suspects in the murder of Christina Krypto.
> It's your job to break into that router and see what you can find.

disclosure: i checked these challenge before release to ensure they were
solvable before the competition occurred. as a result, my solve likely took
longer than the allocated time within the competition. that being said, I did
not participate in the CTF at all

## about the program

there isn't too much going on with regard to the program. from the user's end,
the user is prompted for a command, and a starting location. on the inside, the
program will actually read the flag into a global buffer

```c
/* global buffer `flag_buffer` is passed in as the first parameter */

void read_flag(char *param_1)

{
  long lVar1;
  FILE *__stream;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  __stream = fopen("flag.txt","r");
  if (__stream == (FILE *)0x0) {
    puts("Flag cannot be found, contact the CTF organizers.");
                    /* WARNING: Subroutine does not return */
    exit(5);
  }
  fgets(param_1,0x3f,__stream);
  fclose(__stream);
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

from here, we can see that the command that user is prompted for doesn't do much
but be printed out (cough), and the location to start is treated as a buffer to
copy `0x3f` bytes from before printing it out.

```c
void vuln(void)

{
  long in_FS_OFFSET;
  void *local_60;
  char local_58 [63];
  undefined1 local_19;
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  local_60 = (void *)0x0;
  puts("-- netrunnerware bot v1.2 --");
  strncpy(local_58,"vasvygengvba_cynaarq_njnvgvat_pbasvezngvba",0x40);
  printf("Any commands? ");
  fgets(local_58,0x3f,stdin);
  printf("Roger, preparing to execute: ");
  printf(local_58);
  printf("Where do I start? ");
  __isoc99_fscanf(stdin,"%lld",&local_60);
  getchar();
  memcpy(local_58,local_60,0x3f);
  local_19 = 0;
  printf("Finished command: %s\n",local_58);
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

therefore, it would be really nice to know the exact location of where the flag
is stored in memory such that `memcpy` can copy it out and the subsequent
`printf` call can print it. the issue here is, the address to the location of
the flag is actually unknown, as the binary is made position independent, and
ASLR is enabled. therefore, there is no good way to know where the buffer is at
any given run of the program.

## vulnerability

right in the `vuln` function, there is a compsci teacher's worst nightmare, that
being a call on `printf` with user-controlled buffer as its first parameter. the
core reason why this is vulnerable can confirmed through reference with the
documentation on `printf`, where the signature of the function is the following:

```c
int printf(const char *restrict format, ...);
```

that is, the first parameter is treated as the format specifier. in most
circumstances, this allows developers to print changing data to the users
through a single interface. this is able to print out everything, from numeric
values stored in memory, to hexadecimal representations of the bytes in memory,
to any non-format-ty parts of the provided string. what's more interesting about
this is, `printf` is also a variable-argument function, that is, it is able to
use virtually any number of arguments. the number of arguments the function
should look into parsing is based off the format specifier. therefore, if the
user is able to manipulate the format specifier, they would be able to
manipulate the number of parameters `printf` believes to have access to.

the dangers of controllable format specifiers become apparent when the way in
which parameters are passed into functions. this very much depends on the
platform and architecture, but for the sake of this writeup, I'll be focusing
soley on Linux `x86-64`. here, arguments are initially placed in a set of
6 registers. if there are more than 6 arguments required by a function, then
arguments are then pushed onto the stack. that is, the following list would show
where arguments pull arguments from.

1. `rdi`
2. `rsi`
3. `rdx`
4. `rcx`
5. `r8`
6. `r9`
7. `*rsp`
8. `*(rsp + 8)`
9. `*(rsp + 16)`
10. (and so on)

as a result, being able to control the parameters to which `printf` reads from
then allows the stack to be read. it is important to note that `printf` will
read down the stack. therefore, `printf` would be able to look anywhere into the
current stack frame, but also out of it into caller stack frames.

in our use case, we actually want to use this to leak an address in memory,
namely to determine where the binary itself is located.
