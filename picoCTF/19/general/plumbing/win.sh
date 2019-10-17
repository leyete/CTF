#!/bin/sh
nc 2019shell1.picoctf.com 9525 | grep -oE 'picoCTF\{.*\}'
