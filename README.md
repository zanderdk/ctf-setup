#My CTF setup

##discalimer

this is a product of years of ctf'ing, developed mainly doing ctf's with limited time so features are implented as fast as possible and therefore a lot of crap code was born here.

## Requirements
- gdb
- pwndbg (pull from git and place in /opt/pwndbg, see .gdbinit for more info)
- patchelf
- tmux
- splitmind https://github.com/jerdna-regeiz/splitmind (pull from git and use my setupSplitmind.py. again see .gdbinit for more info)
- pwntools (i recommend using master from git and not from what ever package manger you are using)


## Installing

copy my gdbinit into you home directory /home/${USER}/.gdbinit (be aware of the . infront of gdbinit)
pull splitmind and copy my setupSplitmind.py into the splitmind folder you just pulled
change path for splitmind setup file in .gdbinit

you should be ready

## Running

just run .`/attach.sh`

inside attach.sh you find difrent ways of running the exploits both remote and local with diffrent versions of libc. :-)
the program that you want to debug is also specified in attach.sh

before running `./attach.sh` you have to be inside a tmux session!!!!! as split mind uses tmux to split screens.
pressing ctl-b followed by f and enter you can navigate tmux windows.

now start developing exploit in exploit.py

### tricks

you automaticaly have access to libc and ld as variabels in exploit.py
https://docs.pwntools.com/en/stable/elf.html

you can disable and enable aslr as you like in attach.sh

breakpoints can be two things a absolut hex address to where you want to break:
`b *(0xdeadbeef)`
or `pie 0x5df` some offset into the pie file
you can also do:

`pie 0x1234 libc`
if you wan't to break at offset inside of libc:

`b system`
`b malloc.c:1003`
you can also break at function names or line numbers if your file contains debug info or symbols
to make this work you also need a fork of libc inside this folder... (year i know not the best solution)


`extras` is extra commands passed to gdb at init, here you can fx control how you would like to handle forks in gdb.

#Happy pwning!
