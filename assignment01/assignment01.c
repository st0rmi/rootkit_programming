#include <linux/module.h>
#include <linux/kernel.h>
#include "sysmap.h"

// create the function nr_processes() to be used later 
typedef int func(void);
func* nr_processes = (func*) sysmap_nr_processes;

/*
 * Prints the number of processes to the kernel log.
 */
int print_nr_procs(void)
{
	unsigned int procs;
	procs = 0;

	procs = nr_processes();
	printk(KERN_INFO "There are currently %d processes running.\n", procs);

	return 0;
}

int init_module(void)
{
	printk(KERN_INFO "Welcome! Loading kernel module assignment01.\n");
	
	print_nr_procs();

	return 0;
}

void cleanup_module(void)
{
	printk(KERN_INFO "Unloading kernel module assignment01. Bye!\n");
}
