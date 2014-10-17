#! /bin/bash

# check if a file by the name sysmap.h already exists and back it up
# if necessary
[ -f ./sysmap.h ] && mv sysmap.h sysmap.h.old


cat /boot/System.map-`uname -r` | 
	grep -P "\s+[RDT]+\s" |
	sed 's/^\([^ ]*\) \([^ ]*\) \([^ ]*\)$/#define sysmap_\3 0x\1/g' >>sysmap.h
