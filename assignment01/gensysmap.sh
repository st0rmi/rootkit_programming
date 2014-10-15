#! /bin/bash

mv sysmap.h sysmap.h.old
cat /boot/System.map-`uname -r` |
grep -P "\s+[RDT]+\s" |
sed 's/^\([^ ]*\) \([^ ]*\) \([^ ]*\)$/#define \3 \1/g' >>sysmap.h
