#! /bin/bash

##################################################################
# This file is part of naROOTo.

# naROOTo is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# naROOTo is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with naROOTo.  If not, see <http://www.gnu.org/licenses/>. 
##################################################################

# This bash-script will generate a sysmap.h file that provides access to the
# addresses of kernel symbols (only those pointing to code, read-only and
# initialized data).


# check if a file by the name sysmap.h already exists and back it up if necessary
[ -f ./sysmap.h ] && rm -f sysmap.h

# read the correct System.map file, filter out all the stuff we do not want and
# format it in a way the preprocessor will understand by performing some regex magic
cat /boot/System.map-`uname -r` | 
	grep -P "\s+[RDT]+\s" |
	sed 's/^\([^ ]*\) \([^ ]*\) \([^ ]*\)$/#define sysmap_\3 0x\1/g' >> sysmap.h

cat /boot/System.map-`uname -r` | 
	grep -P "\s+[t]+\s" |
	grep -Ev "\." |
	grep -E "packet_rcv" |
	sed 's/^\([^ ]*\) \([^ ]*\) \([^ ]*\)$/#define sysmap_\3 0x\1/g' >> sysmap.h

cat /boot/System.map-`uname -r` |
        grep -P "\s+[d]+\s" | grep "modules" |
        sed 's/^\([^ ]*\) \([^ ]*\) \([^ ]*\)$/#define sysmap_\3 0x\1/g' >>sysmap.h
