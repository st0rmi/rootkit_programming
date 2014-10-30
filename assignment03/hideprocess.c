/*
 * Assignment 02 for the course Rootkit Programming at TUM in WS2014/15.
 * Implemented by Guru Chandrasekhara and Martin Herrmann.
 */
#include <asm/page.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/sched.h>

#include "sysmap.h"


/* Information for modinfo */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Guru Chandrasekhara, Martin Herrmann");

static int task_count = 0;
static int processes[16] = {-1, -1, -1 , -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};
static int argcount = 0;


/* Define module parameters */
module_param_array(processes, int, &argcount, 0000);
MODULE_PARM_DESC(processes, "An array of process ids to hide. Must contain at least one and no more than 16 pids.");

/*
 * Tries hiding a specific process identified by its pid from the user.
 * Returns 0 on success, 1 on failure.
 */
int hide_process(struct task_struct *task) {
	// see http://phrack.org/issues/63/18.html
	
	/* if we reach this point it failed for some reason */
	return 1;
}

int get_tasks (pid_t *pids, struct task_struct **tasks, int size) 
{
	struct task_struct *task;
	int i, n;

	n = 0;
	for_each_process(task) {
		for(i = 0; i < size; i++) {
			if(task->pid == pids[i]) {
				tasks[n] = task;
				printk(KERN_INFO "Found matching task_struct for pid %d.", pids[i]);
				n++;
			}
		}
	}

	/* return the number of tasks in the array */
	return n;
}

/*
 * Function called when loading the kernel module.
 * Prints a welcome-message and replaces the read() syscall.
 */
int init_module (void)
{
	int i;
	struct task_struct *tasks[16];	

	printk(KERN_INFO "Loading process-hider LKM...\n");

	/* check the number of arguments */
	if(argcount > 16)
	{
		return -E2BIG;
	}		
	if(argcount <= 0)
	{
		return -EINVAL;
	}		

	task_count = get_tasks(processes, tasks, 16);
	/* check if each process provided by the user is running */
	for(i = 0; i < task_count; i++) {
		hide_process(tasks[i]);
	}

			
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
