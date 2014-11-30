#include "include.h"

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

}

void
accept_command_input (char input)
{
	if(command_counter >= 0 && command_counter < 32) {

		if(input == ' ') {
			command_buffer[command_counter] = '\0';
			state = 2;
		} else if(input == ';') {
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
		if(input == ';') {
			param_buffer[param_counter] = '\0';
			execute_command();	
		} else if(input == '\'') {
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
