obj-m += rootkit_group4.o
rootkit_group4-y := main.o include.o port_knocking.o
ccflags-y = -DDEBUG

all:	sysmap
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

sysmap:
	./gensysmap.sh
	@echo "Generated sysmap.h"

clean:
	@rm -f sysmap.h
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

