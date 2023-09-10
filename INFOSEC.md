# INFOSEC

Probelm Statement - A flag in the form of SHA-256 is hidden in some form in this binary file. 
Your task is to reverse engineer the binary to get the flag. Write a detailed writeup 
(containing the flag) as a markdown file, push any associated code into a private github 
repository, make it public after Thursday 11:59 PM. 

You may use any programming language, binary exploitation tool to solve this task.


## Attempt flow- 

1. file rev

```
rev: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter 
/lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=fe9ddc13d0659e1badb3fd04934d02b4aa60893a, not stripped
```

2. strings rev 

Got : *It's not that easy as you think so*

Okay!

3. strace rev

```
execve("/usr/bin/rev", ["rev"], 0x7fff25b0f590 /* 22 vars */) = 0
brk(NULL)                               = 0x563bbd47e000
arch_prctl(0x3001 /* ARCH_??? */, 0x7fff0ed73e50) = -1 EINVAL (Invalid argument)
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=61566, ...}) = 0
mmap(NULL, 61566, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7fbfd47fb000
close(3)                                = 0
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\360q\2\0\0\0\0\0"..., 832) = 832
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
pread64(3, "\4\0\0\0\20\0\0\0\5\0\0\0GNU\0\2\0\0\300\4\0\0\0\3\0\0\0\0\0\0\0", 32, 848) = 32
pread64(3, "\4\0\0\0\24\0\0\0\3\0\0\0GNU\0\t\233\222%\274\260\320\31\331\326\10\204\276X>\263"..., 68, 880) = 68
fstat(3, {st_mode=S_IFREG|0755, st_size=2029224, ...}) = 0
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7fbfd47f9000
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
pread64(3, "\4\0\0\0\20\0\0\0\5\0\0\0GNU\0\2\0\0\300\4\0\0\0\3\0\0\0\0\0\0\0", 32, 848) = 32
pread64(3, "\4\0\0\0\24\0\0\0\3\0\0\0GNU\0\t\233\222%\274\260\320\31\331\326\10\204\276X>\263"..., 68, 880) = 68
mmap(NULL, 2036952, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7fbfd4607000
mprotect(0x7fbfd462c000, 1847296, PROT_NONE) = 0
mmap(0x7fbfd462c000, 1540096, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x25000) = 0x7fbfd462c000
mmap(0x7fbfd47a4000, 303104, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x19d000) = 0x7fbfd47a4000
mmap(0x7fbfd47ef000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1e7000) = 0x7fbfd47ef000
mmap(0x7fbfd47f5000, 13528, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7fbfd47f5000
close(3)                                = 0
arch_prctl(ARCH_SET_FS, 0x7fbfd47fa540) = 0
mprotect(0x7fbfd47ef000, 12288, PROT_READ) = 0
mprotect(0x563bbcdf1000, 4096, PROT_READ) = 0
mprotect(0x7fbfd4838000, 4096, PROT_READ) = 0
munmap(0x7fbfd47fb000, 61566)           = 0
brk(NULL)                               = 0x563bbd47e000
brk(0x563bbd49f000)                     = 0x563bbd49f000
openat(AT_FDCWD, "/usr/lib/locale/locale-archive", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=3035952, ...}) = 0
mmap(NULL, 3035952, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7fbfd4321000
close(3)                                = 0
openat(AT_FDCWD, "/usr/share/locale/locale.alias", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=2996, ...}) = 0
read(3, "# Locale name alias data base.\n#"..., 4096) = 2996
read(3, "", 4096)                       = 0
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/locale/C.UTF-8/LC_IDENTIFICATION", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=252, ...}) = 0
mmap(NULL, 252, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7fbfd4837000
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache", O_RDONLY) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=27002, ...}) = 0
mmap(NULL, 27002, PROT_READ, MAP_SHARED, 3, 0) = 0x7fbfd4804000
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/locale/C.UTF-8/LC_MEASUREMENT", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=23, ...}) = 0
mmap(NULL, 23, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7fbfd4803000
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/locale/C.UTF-8/LC_TELEPHONE", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=47, ...}) = 0
mmap(NULL, 47, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7fbfd4802000
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/locale/C.UTF-8/LC_ADDRESS", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=131, ...}) = 0
mmap(NULL, 131, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7fbfd4801000
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/locale/C.UTF-8/LC_NAME", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=62, ...}) = 0
mmap(NULL, 62, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7fbfd4800000
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/locale/C.UTF-8/LC_PAPER", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=34, ...}) = 0
mmap(NULL, 34, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7fbfd47ff000
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/locale/C.UTF-8/LC_MESSAGES", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFDIR|0755, st_size=4096, ...}) = 0
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/locale/C.UTF-8/LC_MESSAGES/SYS_LC_MESSAGES", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=48, ...}) = 0
mmap(NULL, 48, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7fbfd47fe000
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/locale/C.UTF-8/LC_MONETARY", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=270, ...}) = 0
mmap(NULL, 270, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7fbfd47fd000
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/locale/C.UTF-8/LC_COLLATE", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=1518110, ...}) = 0
mmap(NULL, 1518110, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7fbfd41ae000
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/locale/C.UTF-8/LC_TIME", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=3360, ...}) = 0
mmap(NULL, 3360, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7fbfd47fc000
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/locale/C.UTF-8/LC_NUMERIC", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=50, ...}) = 0
mmap(NULL, 50, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7fbfd47fb000
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/locale/C.UTF-8/LC_CTYPE", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=201272, ...}) = 0
mmap(NULL, 201272, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7fbfd417c000
close(3)                                = 0
rt_sigaction(SIGINT, {sa_handler=0x563bbcdef990, sa_mask=[INT], sa_flags=SA_RESTORER|SA_RESTART, sa_restorer=0x7fbfd464d210}, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=0}, 8) = 0
rt_sigaction(SIGTERM, {sa_handler=0x563bbcdef990, sa_mask=[TERM], sa_flags=SA_RESTORER|SA_RESTART, sa_restorer=0x7fbfd464d210}, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=0}, 8) = 0
fstat(0, {st_mode=S_IFCHR|0620, st_rdev=makedev(0x88, 0x2), ...}) = 0
read(0,
```

The execution haults here, so terminated the command. Moving on. 

4. objdump -M intel -d rev > disassembly.asm

- to obtain the disabbembly in Intel syntax

5. gdb rev

using gdb to analyse or as a debugger.

 - set disassembly-flavor intel
 - disass *main
  
  ```
  Dump of assembler code for function main:
   0x08048571 <+0>:     push   ebp
   0x08048572 <+1>:     mov    ebp,esp
   0x08048574 <+3>:     and    esp,0xfffffff0
   0x08048577 <+6>:     sub    esp,0x10
   0x0804857a <+9>:     mov    DWORD PTR [esp],0x8048664
   0x08048581 <+16>:    call   0x8048350 <printf@plt>
   0x08048586 <+21>:    mov    eax,0x0
   0x0804858b <+26>:    leave
   0x0804858c <+27>:    ret
  ```

  - b* main

  ```Breakpoint 1 at 0x8048571```

  we obtain a breakpoint, next we try and run it.

  - run

  ```Starting program: /mnt/c/Users/HP/swetak/hack101/rev
/bin/bash: /mnt/c/Users/HP/swetak/hack101/rev: No such file or directory
During startup program exited with code 127.```

  *Reason : the config of rev as mentioned in 1st command, is 32-bit, while gdb is compatible with 64-bit*


6. sudo dpkg --add-architecture i386
7. sudo apt-get update
8. sudo apt-get install libc6:i386 libncurses5:i386 libstdc++6:i386

9. Go back to 5

    - run
    ```Starting program: /mnt/c/Users/HP/swetak/hack101/rev```

    - si
    ```0x08048572 in main ()```

    - u
    ```0x08048574 in main ()```

    - u *0x08048574
    ```0xf7deaee5 in __libc_start_main () from /lib/i386-linux-gnu/libc.so.6```

    - u *0xf7deaee5
    ```It's not that easy as you think so[Inferior 1 (process 1002) exited normally]```

    ** Back to square 1**


## Result - Nowhere near to the flag.
