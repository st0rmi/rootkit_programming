/*
 * This file contains many different helper functions that are needed
 * throughout the program.
 */
#include <linux/fdtable.h>
#include <linux/sched.h>
#include <linux/slab.h>

#include "include.h"



/*
 * Get PID from the name.
 */
int
convert_atoi(char *str)
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

/*
 * Disable the writing protection for the whole processor.
 */
void
disable_page_protection (void)
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
void
enable_page_protection (void)
{
	unsigned long value;
	asm volatile("mov %%cr0,%0" : "=r" (value));
	if (!(value & 0x00010000))
	{
		value |= 0x00010000;
		asm volatile("mov %0,%%cr0": : "r" (value));
    	}
}

/* Gets the absolute path to a file identified by fd */
ssize_t
get_path(unsigned int fd, char *path, size_t bufsiz)
{
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
	path_len = strlen(cwd);
	
	/* check whether the supplied buffer is big enough */
	if(path_len > bufsiz) {
		return -ENOMEM;
	}
	
	memcpy(path, cwd, path_len);
	kfree(buf);
	
	return strlen(cwd);
}
