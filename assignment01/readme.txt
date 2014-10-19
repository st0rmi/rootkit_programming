Files inside : 
	1. mod.c - LKM
	2. gensysmap.sh - bash script to generate sysmap.h in the current directory
	3. sysmap.h - sysmap.h generated from gensysmap.h
	4. Makefile
	5. Readme.txt

How to? 

1. Run the gensysmap.sh script to generate sysmap.h
	$sh ./gensysmap.sh

2. Build kernel module
	$make
	> mod.ko and other object files will be generated, we are interested in mod.ko

3. Before loading the kernel module change the console logging level of printk.
	$ echo "7" > /proc/sys/kernel/printk

4. Load the mod.ko from system console.
	$insmod mod.ko
	> you should be able to see the welcome-message followed by the number of processes currently running on the system.
	> you can verify this by $ cat /var/log/messages
	> check the loaded modules using $ cat /proc/modules
		you should be able to see mod on top of the list

5. Unload the module. 
	$ rmmod mod
	> you should be able to see goodbye-message.

