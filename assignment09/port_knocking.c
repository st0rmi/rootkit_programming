
/*
 * This file provides all the functionality needed for port knocking.
 */
#include <net/ip.h>
#include <linux/inet.h>

#include "include.h"
#include "main.h"


void
load_port_knocking (char *ipv4_addr, unsigned int port_number)
{
	ROOTKIT_DEBUG("Starting to load the port knocking...\n");


	ROOTKIT_DEBUG("Done.\n");
}

void
unload_port_knocking (void)
{
	ROOTKIT_DEBUG("Starting to unload the port knocking...\n");


	ROOTKIT_DEBUG("Done.\n");
}
