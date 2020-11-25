from pwn import *
from struct import pack
import argparse
from typing import List
from shutil import copyfile
import os
import stat
import subprocess
from time import sleep
import atexit
import re
from subprocess import check_output

#settings
#terminalSetting = ['termite', '-e']
terminalSetting = ['tmux', 'new-window']
dockerSettings = ['tmux', 'new-window']
systemLd = '/usr/lib/ld-linux-x86-64.so.2'
systemLibc = '/usr/lib/libc.so.6'
dockerLd = '/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2'
dockerLibc = '/lib/x86_64-linux-gnu/libc.so.6'
dockerRunPath = '/root/'
pwndbgSettings = '''
set context-code-lines 10
set context-stack-lines 8
set context-sections "regs disasm code stack backtrace"
'''

gefSettings = '''
gef config context.layout "legend regs code args source memory stack"
gef config context.nb_lines_code 8
gef config context.nb_lines_stack 4
'''

def u64Var(addr: bytes):
    return u64(addr + b'\x00' * ( 8 - len(addr) ))

def u32Var(addr: bytes):
    return u32(addr + b'\x00' * ( 4 - len(addr) ))

def str2bool(v):
    if isinstance(v, bool):
       return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')

parser = argparse.ArgumentParser(description='pwn script for CTF. You can also use the pwntools arguments such as NOASLR')
parser.add_argument('--args', dest='args', default=None,
                    help='the arguments provided to the program. This can also be set programmatically')
parser.add_argument('--program', dest='program', default=None,
                    help='program to run if not specified in code.')
parser.add_argument('--gdbplugin', dest='gdbplugin', default=None,
                    help='chose gdb init script gef pwndbg or path (default: ~/.gdbinit)')
parser.add_argument('--libc', dest='libc', default=systemLibc,
                    help='libc path (defaults: system libc 64bit). For gef heap stuff to work name cannot be libc.so.6')
parser.add_argument('--ld', dest='ld', default=systemLd,
                    help='ld path (defaults: system ld 64bit)')
parser.add_argument('--pre-load-extras', dest='preloadExtras', default=None,
                    help='extra files to preload')
parser.add_argument('--libraries', dest='libraries', default=None,
                    help='sets the LD_LIBRARY_PATH (default is None)')
parser.add_argument('--extra-src-dir', dest='srcDirs', default=[],
                    help='extra dirs to search for src files')
parser.add_argument('--exec', dest='exec', default='attach',
                    help='how to execute debug/local/remote/attach')
parser.add_argument('--exe', dest='exe', default=None,
                    help='the elf passed to gdb')
parser.add_argument('--host', dest='host', default='None',
                    help='ip of remote host')
parser.add_argument('--port', dest='port', default=None,
                    help='port of remote host')
parser.add_argument("--solid-events", dest='events', type=str2bool, nargs='?',
                        const=True, default=False,
                        help="break on solid events such as lib loading")
parser.add_argument("--auto-patch", dest='patch', type=str2bool, nargs='?',
                        const=True, default=False,
                        help="break on solid events such as lib loading")
parser.add_argument("--pre-load-ld", dest='preloadld', type=str2bool, nargs='?',
                        const=True, default=False,
                        help="if true preload the specified ld")
parser.add_argument("--pre-load-libc", dest='preloadlibc', type=str2bool, nargs='?',
                        const=True, default=False,
                        help="if true preload the specified libc")
parser.add_argument("--inside-docker", dest='insideDocker', type=str2bool, nargs='?',
                        const=True, default=False,
                        help="DONT USE THIS! for running inside the docker container only")
parser.add_argument("--docker", dest='docker', type=str2bool, nargs='?',
                        const=True, default=False,
                        help="run inside docker")
parser.add_argument('--extra-docer-param', dest='dockerParam', default='',
                    help='extra docker parameters')
parser.add_argument('--attach-to', dest='attachTo', default='',
                    help='extra docker parameters')

args = parser.parse_args()

def get_pid(name):
    return min([int(x) for x in check_output(["pidof",name]).split()])

def parseBreakPoints(breakpoints: str, path: str, pid: int = None):
    if not pid:
        for x in breakpoints.split('\n'):
            if 'pie' in x:
                log.warning('pie breakpint only supported in attach mode!')
                break
        return breakpoints
    else:
        with open('/proc/'+ str(pid) + '/maps', 'r') as f:
            maps = f.read()
        objs = []
        for l in maps.split('\n')[:-1]:
            l = l.split()
            obj = {'start': int(l[0].split('-')[0],16), 'end': int(l[0].split('-')[1], 16), 
            'permission': l[1], 'offset': l[2], 'device': l[3], 'indode': l[4],
            'path': l[5] if len(l) == 6 else 'data'}
            objs.append(obj)
        mainObj = sorted([x for x in objs if x['path'] == path], key=lambda x: x['start'])
        if mainObj:
            mainObj = mainObj[0]
        else:
            mainObj = None
        newBreakpoints = []
        for l in breakpoints.split('\n'):
            if l:
                if l[:3] == 'pie':
                    if len(l.split(' ')) == 3:
                        val = int(l.split(' ')[1], 16)
                        path = l.split(' ')[2]
                        obj = sorted([x for x in objs if path in x['path']], key=lambda x: x['start'])[0]
                        val = obj['start'] + val
                        newBreakpoints.append('b *' + hex(val))
                    else:
                        if mainObj:
                            val = int(l.split('pie ')[1], 16)
                            val = mainObj['start'] + val
                            newBreakpoints.append('b *' + hex(val))
                else:
                    newBreakpoints.append(l)
        newBreakpoints = '\n'.join(newBreakpoints)
        return newBreakpoints

def fast_scandir(dirname):
    subfolders= [f.path for f in os.scandir(dirname) if f.is_dir()]
    for dirname in list(subfolders):
        subfolders.extend(fast_scandir(dirname))
    return subfolders

def setup(elfPath: str, breakpoints: str, progArgs: List[str] = None, extraGdbSettings: str = ''):
    gdbSettings = '''set breakpoint pending on\n'''

    if args.gdbplugin == 'gef':
        args.gdbplugin = './gefinit'
        gdbSettings += gefSettings
    elif args.gdbplugin == 'pwndbg':
        args.gdbplugin = './pwndbginit'
        gdbSettings += pwndbgSettings
    else:
        args.gdbplugin = None
    

    if args.events:
        gdbSettings += 'set stop-on-solib-events 1'

    if elfPath is None:
        if args.program is None:
            log.error('no program argument!')
            return
        elfPath = args.program

    args.libc = os.path.abspath(args.libc)
    elfPath = os.path.abspath(elfPath)
    args.ld = os.path.abspath(args.ld)

    if args.docker:
        with open('/proc/self/cmdline') as f:
            cmd = f.read()
        cmd = cmd.split('\x00')[:-1]
        cmd = ' '.join(cmd)
        pattern = re.compile("--docker\s+True\s*", re.IGNORECASE)
        cmd = pattern.sub('', cmd)
        pattern = re.compile("--docker\s*", re.IGNORECASE)
        cmd = pattern.sub('', cmd)
        cmd = [x for x in cmd.split()]
        cmd.insert(2, '--inside-docker')
        cmd = ' '.join(cmd)
        containerName = elfPath.replace('/', '').replace('\\', '').lower()
        p = subprocess.run('docker image ls'.split(), capture_output=True)
        out = p.stdout.decode('utf-8')
        if containerName not in out:
            buildCmd = 'docker build -t ' + containerName + ' .'
            p = subprocess.run(buildCmd.split(), capture_output=True)
            if p.stderr:
                log.success('docker build failed')
                print(p.stderr)
            else:
                log.success('docker build done')
        else:
            log.info('docker already exists')

        kill = 'docker kill ' + containerName
        p = subprocess.run(kill.split(), capture_output=True)
        if p.stdout:
            log.info('killed old container')

        runCmd = 'docker run -p 1024:1024' + args.dockerParam + ' --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -d --name ' + containerName + ' --rm -it ' + containerName
        p = subprocess.run(runCmd.split(), capture_output=True)
        if p.stdout:
            log.success('docker container running')

        newSesCmd = 'docker exec -it ' + containerName + ' tmux new-session -d -s debug'
        p = subprocess.run(newSesCmd.split(), capture_output=True)
        with open('.debugDocker.sh', 'w') as f:
            f.write('#!/bin/bash\n')
            f.write('tmux send-keys -t debug.0 "' + cmd + '" ENTER\n')
        
        p = subprocess.run(('docker cp setup.py ' + containerName + ':' + dockerRunPath + '/setup.py').split(), capture_output=True)
        p = subprocess.run(('docker cp exploit.py ' + containerName + ':' + dockerRunPath + '/exploit.py').split(), capture_output=True)
        p = subprocess.run(('docker cp .tmux.conf ' + containerName + ':/root/.tmux.conf').split(), capture_output=True)
        p = subprocess.run(('docker cp setupSplit.py ' + containerName + ':' + dockerRunPath + '/setupSplit.py').split(), capture_output=True)
        p = subprocess.run(('docker cp .debugDocker.sh ' + containerName + ':' + dockerRunPath + '/.debugDocker.sh').split(), capture_output=True)
        p = subprocess.run(('docker exec -it ' + containerName + ' chmod +x ' + dockerRunPath + '/.debugDocker.sh').split(), capture_output=True)
        p = subprocess.run(('docker exec -it ' + containerName + ' sh ' + dockerRunPath + '/.debugDocker.sh').split(), capture_output=True)
        p = subprocess.run(('docker cp httpd.conf ' + containerName + ':/usr/local/apache2/conf/httpd.conf').split(), capture_output=True)

        cmd = 'docker exec -it ' + containerName + ' tmux a -t debug'

        os.system(cmd)
        print(containerName)
        quit()

    if args.patch:
        newPath = '/tmp/patchedExec'
        copyfile(elfPath, newPath)
        cmd = 'patchelf --set-interpreter ' + args.ld + ' ' + newPath
        log.info('patching elf: ' + cmd)
        cmd = cmd.split()
        p = subprocess.run(cmd, capture_output=True)
        output = p.stderr
        if output:
            output = output.decode('utf-8').split('warning: ')[1]
            log.warning(output)
        st = os.stat(newPath)
        os.chmod(newPath, st.st_mode | stat.S_IEXEC)
        elfPath = newPath

    preloadString = ''
    if args.preloadld:
        preloadString = args.ld     
    
    if args.preloadlibc:
        if preloadString != '':
            preloadString += ' '
        preloadString += args.libc
    
    if args.preloadExtras:
        preloadString += ' ' + args.preloadExtras

    env = os.environ.copy()
    
    if preloadString != '':
        env["LD_PRELOAD"] = preloadString
    if args.libraries:
        args.libraries = os.path.abspath(args.libraries)
        env["LD_LIBRARY_PATH"] = args.libraries
    
    if args.insideDocker:
        if args.libc == systemLibc:
            args.libc = dockerLibc
        if args.ld == systemLd:
            args.ld = dockerLd
        if args.gdbplugin is None:
            context.clear(terminal=dockerSettings, binary = ELF(elfPath)) 
        else:
            context.clear(terminal=dockerSettings, gdbinit=args.gdbplugin, binary = ELF(elfPath))
    else:
        if args.gdbplugin is None:
            context.clear(terminal=dockerSettings, binary = ELF(elfPath))
        else:
            context.clear(terminal=terminalSetting, gdbinit=args.gdbplugin, binary = ELF(elfPath))
    elf = context.binary

    if progArgs is None:
        if args.args:
            prog = [elf.path] + args.args.split(' ')
        else:
            prog = [elf.path]
    else:
        prog = [elf.path] + progArgs
    
    pid = None

    if args.insideDocker:
        runPath = dockerRunPath
    else:
        runPath = './'
    runPath = os.path.abspath(runPath)
    
    glibcPath = runPath + '/glibc'
    if os.path.isdir(glibcPath):
        dirs = fast_scandir(glibcPath)
        dirs = ['dir ' + x for x in dirs]
        dirs = '\n'.join(dirs)
        dirs += '\ndir ./'
    else:
        dirs = '\ndir ./'
    extraGdbSettings += dirs
    
    if args.srcDirs and os.path.isdir(args.srcDirs):
        dirs = fast_scandir(args.srcDirs)
        dirs = ['dir ' + x for x in dirs]
        dirs = '\n'.join(dirs)
        extraGdbSettings += dirs    
    
    if args.exec == 'scriptRemote':
        io = process(args.program.split())
        #sleep(5)
        gdbSettings += parseBreakPoints(breakpoints, elfPath, pid) + extraGdbSettings
        host, port = args.host, int(args.port)
        pwnlib.gdb.attach((host, port), gdbSettings, exe = elfPath if not args.exe else args.exe)
    if args.exec == 'script':
        p = subprocess.run(args.program.split())
        pid = get_pid(args.attachTo)
        gdbSettings += parseBreakPoints(breakpoints, elfPath, pid) + extraGdbSettings
        io = None
        pwnlib.gdb.attach(pid, gdbSettings)
    if args.exec == 'attach':
        print(prog)
        print(preloadString)
        io = process(prog, env=env)
        pid = io.pid
        gdbSettings += parseBreakPoints(breakpoints, elfPath, pid) + '\n' + extraGdbSettings
        print(gdbSettings)
        pwnlib.gdb.attach(io, gdbSettings)
    if args.exec == 'debug':
        gdbSettings += parseBreakPoints(breakpoints, elfPath) + '\n' + extraGdbSettings
        io = pwnlib.gdb.debug(prog, env=env)
        pid = io.pid
    if args.exec == 'local':
        io = process(prog, env=env)
        pid = io.pid
    if args.exec == 'remote':
        io = remote(args.host, args.port)
    if 'ld' in args.exec:
        if not args.libraries:
            log.info('no libary path specified using ./')
            env["LD_LIBRARY_PATH"] = './src'
        libsoPath = env["LD_LIBRARY_PATH"] + '/libc.so.6'
        if os.path.exists(libsoPath):
            os.remove(libsoPath)
        cmd = 'ln -s ' + args.libc + ' ' + libsoPath
        log.info('creating libc.so.6: ' + cmd)
        cmd = cmd.split()
        p = subprocess.run(cmd, capture_output=True)
        prog = [args.ld] + prog
        if args.exec == 'ldAttach':
            io = process(prog, env=env)
            pid = io.pid
            gdbSettings += parseBreakPoints(breakpoints, elfPath, pid) + '\n' + extraGdbSettings
            pwnlib.gdb.attach(io, gdbSettings)
        if args.exec == 'ldDebug':
            gdbSettings += parseBreakPoints(breakpoints, elfPath) + '\n' + extraGdbSettings
            io = pwnlib.gdb.debug(prog, gdbSettings, env=env)
            pid = io.pid

    libc = ELF(args.libc)
    ld = ELF(args.ld)

    return io, pid, elf, libc, ld
