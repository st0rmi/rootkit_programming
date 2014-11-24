#! /bin/bash
# This bash-script will generate a sysmap.h file that provides access to the
# addresses of kernel symbols (only those pointing to code, read-only and
# initialized data).

# read the correct System.map file, filter out all the stuff we do not want and
# format it in a way the preprocessor will understand by performing some regex magic
cat /boot/System.map-`uname -r` | 
	grep -P "\s+[RDT]+\s" |
	sed 's/^\([^ ]*\) \([^ ]*\) \([^ ]*\)$/#define sysmap_\3 0x\1/g' >>sysmap.h
