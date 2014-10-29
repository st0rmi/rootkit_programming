obj-m += hideprocess.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	@rm -f sysmap.h
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

