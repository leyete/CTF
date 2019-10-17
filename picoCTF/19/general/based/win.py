#!/usr/bin/env python2

import pwn

'''
picoCTF '19

Challenge: Based
Category:  General Skills
Points:    200
'''

def decode(base, string):
    result = ''
    if base == 16:
        result = string.decode('hex')
    else:
        for i in string.split(' '):
            result += chr(int(i, base))
    return result

# Challenge solution

r = pwn.remote('2019shell1.picoctf.com', 29594)
for base in [2, 8, 16]:
    r.recvuntil('the ')
    r.sendlineafter('Input:', decode(base, r.recvuntil(' as a word.', drop=True).strip()))

r.recvuntil('Flag: ')
print 'Flag: ' + r.recvline(),
