/*
 * Assignment 02 for the course Rootkit Programming at TUM in WS2014/15.
 * Implemented by Guru Chandrasekhara and Martin Herrmann.
 */
#include <asm/page.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/unistd.h>
#include <linux/init.h>
#include <linux/stat.h>

#include "sysmap.h"

/* Information for modinfo */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Guru Chandrasekhara, Martin Herrmann");



/* Define module parameters */
static int hideprocess_processes[16] = {-1, -1, -1 , -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};
static int hideprocess_argcount = 0;

module_param_array(hideprocess_processes, int, &hideprocess_argcount, 0000);
MODULE_PARM_DESC(hideprocess_processes, "An array of process ids to hide");

/*
 * Tries hiding a specific process identified by its pid from the user.
 * Returns 0 on success, 1 on failure.
 */
int hide_process(pid_t pid) {
	// TODO:
	// see http://phrack.org/issues/63/18.html
	return 1;
}

/*
 * Function called when loading the kernel module.
 * Prints a welcome-message and replaces the read() syscall.
 */
int init_module (void)
{
	printk(KERN_INFO "Loading process-hider LKM...\n");
	
	/* check if each process provided by the user is running */
	// TODO: call hide_process(pid);
	
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
