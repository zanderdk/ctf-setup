#!/bin/sh

# running with specific libc and ld (prefered way)
# ld and libc should be placed in the same folder as exploit.py and setup.py or give it absolut path
python exploit.py --libc libc-2.32.so --ld ld-2.32.so --auto-patch True --pre-load-libc True --exec attach --program chall
# running without aslr
# python exploit.py --libc libc-2.32.so --ld ld-2.32.so --auto-patch True --pre-load-libc True --exec attach --program chall NOASLR

# if you don't know libc version use this.
# this will use your os's libc
# python exploit.py --exec attach --program chall

# remote attacking with specific libc (preferd remote attack)
# python exploit.py --libc libc-2.32.so --ld ld-2.32.so --host 127.0.0.1 --port 1337 --exec remote --program chall

# remote attack without specific libc
# python exploit.py --host 127.0.0.1 --port 1337 --exec remote --program chall


