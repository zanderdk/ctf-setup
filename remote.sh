#!/bin/sh
#python exploit.py --libc libc-2.31.so --ld ld-2.31.so --auto-patch True --pre-load-libc True --exec attach --program chall
python exploit.py  --exec remote --host 127.0.0.1 --port 1024 --program chall