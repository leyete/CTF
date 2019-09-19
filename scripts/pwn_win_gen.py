#!/usr/bin/env python3

import argparse
import os.path as path

'''
Generate a win.py script under the current working directory.
'''

parser = argparse.ArgumentParser(description='Win script generator')
parser.add_argument('-b', '--binary', help='Sample of the binary', nargs='?', default=None)
parser.add_argument('-l', '--libc', help='Local copy of the libc', nargs='?', default=None)
parser.add_argument('-t', '--target', help='Remote target hostname/address', nargs='?', default=None)
parser.add_argument('-p', '--port', help='Target listening port', nargs='?', default=None, type=int)
args = parser.parse_args()

# Read the template file
template = ''
with open(path.expandvars('$HOME/CTF/templates/pwn_win.py'), 'r') as f:
    template = f.read()

# Replace the configuration parameters
template = template.replace('binary = None', f'binary = {args.binary.__repr__()}')
template = template.replace('libc = None', f'libc = {args.libc.__repr__()}')
template = template.replace('host = None', f'host = {args.target.__repr__()}')
template = template.replace('port = None', f'port = {args.port.__repr__()}')

# Write the win.py script
with open('./win.py', 'w') as f:
    f.write(template)

print('[+] win.py generated!')
