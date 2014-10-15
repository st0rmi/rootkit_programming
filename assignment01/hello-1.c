#include <linux/module.h>
#include <linux/kernel.h>

int init_module(void)
{
	printk(KERN_INFO "Hello, my name is Bender!\n");

	return 0;
}

void cleanup_module(void)
{
	printk(KERN_INFO "Screw that, I'll compile my own kernel to load into - with blackjack and hookers!\n");
}
