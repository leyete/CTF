#!/usr/bin/env python3

from ctypes import cdll
import pwn

'''
seed SPRiNG challenge solution from picoCTF '19
'''

# Load GLIBC
libc = cdll.LoadLibrary('libc.so.6')

level = 1
print('[*] Cracking PRNG ...')
for i in range(-100, 101):
    seed = libc.time() + i
    r = pwn.remote('2019shell1.picoctf.com', 4160, level='CRITICAL')

    # Seed the PRNG
    libc.srand(seed)

    # Send the attempt to the target
    r.sendlineafter('Guess the height: ', f'{libc.rand() & 0xf}')
    a = r.recvline()
    while b'WRONG!' not in a:
        print(f'[*] Possible seed found')
        r.sendlineafter('Guess the height: ', f'{libc.rand() & 0xf}')
        a = r.recvline()
        print(f'\t{a}')

    else:
        print(f'{i} : {a}')
