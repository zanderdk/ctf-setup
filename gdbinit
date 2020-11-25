# importing pwndbg
source /opt/pwndbg/gdbinit.py

# import splitmind settings
# in this file you can change window sizes and much more
# https://github.com/jerdna-regeiz/splitmind for more info
source /home/zander/Projects/splitmind/setupSplit.py

#pwndbg settings
# set context-code-lines 10
# set context-stack-lines 8
# set context-sections "regs disasm code stack backtrace"


# for kernel debugging
# add-auto-load-safe-path /home/zander/Projects/pwning/zer0pts/meowmow/linux-stable/scripts/gdb/vmlinux-gdb.py
