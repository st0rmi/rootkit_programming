#ifndef PORT_KNOCK_HEADER
#define PORT_KNOCK_HEADER

#include "include.h"

#define PROTO_TCP 6
#define PROTO_UDP 17

int
load_port_knocking (char *, unsigned int, int);

void
unload_port_knocking (void);

#endif
