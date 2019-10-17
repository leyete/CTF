#!/usr/bin/env python3

'''

'''


# (1) read both files

KITTERS = b''
CATTOS  = b''

with open('./kitters.jpg', 'rb') as file:
    KITTERS = file.read()

with open('./cattos.jpg', 'rb') as file:
    CATTOS = file.read()

# (2) analyze the differences
differences = {'kitters': [], 'cattos': []}
for i in range(len(KITTERS) if len(KITTERS) <= len(CATTOS) else len(CATTOS)):
    if KITTERS[i] != CATTOS[i]:
        differences['kitters'].append(KITTERS[i])
        differences['cattos'].append(CATTOS[i])

# (3) print the flag hidden in cattos
print(b''.join(differences['cattos']).decode('utf-8'))
