obj-m += rootkit_group4.o
rootkit_group4-y := main.o include.o getdents.o
ccflags-y = -std=gnu99 -Wno-declaration-after-statement

all:
	./gensysmap.sh
	@echo "Generated sysmap.h"
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	@rm -f sysmap.h
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

