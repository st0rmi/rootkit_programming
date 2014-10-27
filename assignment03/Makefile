obj-m += hideprocess.o

all:
	@echo "Generating sysmap.h ..."
	@./gensysmap.sh
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	@rm -f sysmap.h
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

