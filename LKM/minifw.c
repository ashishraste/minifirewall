#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/string.h>

#include <linux/vmalloc.h>
#include <linux/skbuff.h>
#include <linux/sched.h>
#include <linux/netfilter.h>
#include <asm/uaccess.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/netfilter_ipv4.h>		// has the netfilter hook's structure

#include "minifw.h"     

#define MAX_RULE_LENGTH 	PAGE_SIZE
#define MAX_RULES 			100
#define RULE_DOES_NOT_MATCH 1
#define RULE_MATCHES      	0
#define UID_MAX        		256

//#define __KERNEL__
//#define MODULE

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("minifw Loadable Kernel Module");
MODULE_AUTHOR("Ashish Raste");

static struct 			proc_dir_entry *proc_entry;
static my_iptable 		minifw_rules_table[MAX_RULES];
static my_iptable 		*my_ipt;
static struct 			nf_hook_ops nfho_in;
static struct 			nf_hook_ops nfho_out;
static unsigned char 	allowed_users[MAX_RULES];

static unsigned char	num_of_rules;
static unsigned int 	rule_index;
static unsigned int 	next_rule_ctr;

unsigned int minifw_inbound_filter(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in,
									const struct net_device *out, int (*okfn)(struct sk_buff *));
unsigned int minifw_outbound_filter(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in,
									const struct net_device *out, int (*okfn)(struct sk_buff *));
ssize_t minifw_write(struct file *filp, const char __user *buff, unsigned long len, void *data);
ssize_t minifw_read( char *page, char **start, off_t off, int count, int *eof, void *data);

// function prototypes
int Check_Rule(struct sk_buff *skb, my_iptable *my_ipt);
int Check_IP(const unsigned char *ip_addr1, const unsigned char *ip_addr2, const char *net_mask, const unsigned char bmask);
int Check_Protocol(const unsigned short protocol1, const unsigned short protocol2,	const unsigned char bmask);
int Check_Port(const unsigned short port1, const unsigned short port2, const unsigned char bmask);
int Check_Permission(const my_iptable *my_ipt);
int Delete_Rule(const my_iptable *my_ipt);


// definitions of all the functions involved
int init_minifw_read_write_module(void) {
	int ret = 0;
	my_ipt = (my_iptable *)vmalloc(sizeof(my_iptable));
	//printk(KERN_INFO "going to read my_iptable rules\n");
	if(!my_ipt)														// check whether null pointer is returned for my_ipt
		ret = -ENOMEM;
	else {
		memset((char *)my_ipt, 0, sizeof(my_iptable));				// owner-group-others
		proc_entry = create_proc_entry("minifw", 0646, NULL);		// rw-r--rw-, the owner of this entry would have read/write permissions
		if(proc_entry == NULL) {
			ret = -ENOMEM;
			vfree(my_ipt);
			printk(KERN_INFO "minifw: couldn't create proc entry\n");
		}		
		else {
			printk(KERN_INFO "minifw: minifw proc entry succesfully registered\n");
			rule_index = 0;
			next_rule_ctr = 0;
			num_of_rules = 0;
			memset(allowed_users, 0, UID_MAX * sizeof(unsigned char));
			allowed_users[0] = 1;      				// super user with uid 0 should have access to the iptables by default, hence set his flag to 1
	
			proc_entry->read_proc = minifw_read;
			proc_entry->write_proc = minifw_write;
			proc_entry->owner = THIS_MODULE;
			printk(KERN_INFO "minifw: minifw read_write module loaded successfully\n");	
		}		
	}
	return 0;
}

int init_rule_match_module(void) {
	nfho_in.hook		= minifw_inbound_filter;		// filter for inbound packets
	nfho_in.hooknum 	= NF_INET_LOCAL_IN;				// netfilter hook for local machine bounded ipv4 packets
	nfho_in.pf			= PF_INET;						
	nfho_in.priority 	= NF_IP_PRI_FIRST;				// we set its priority higher than other hooks
	nf_register_hook(&nfho_in);
	
	nfho_out.hook		= minifw_outbound_filter;		// filter for outbound packets
	nfho_out.hooknum	= NF_INET_LOCAL_OUT;
	nfho_out.pf			= PF_INET;
	nfho_out.priority	= NF_IP_PRI_FIRST;
	nf_register_hook(&nfho_out);

	printk(KERN_INFO "minifw: rule match module loaded\n");
	return 0;	
}	

int my_init_module(void) {
	init_minifw_read_write_module();
	init_rule_match_module();
	return 0;
}

ssize_t minifw_write(struct file *filp, const char __user *buff, unsigned long len, void *data) {
	int rules_remaining = MAX_RULES - rule_index + 1;		// rules_remaining limits: [0, MAX_RULES]
	int num = len / sizeof(my_iptable);						// get the byte index where the next rule should be written	
	memset(my_ipt, 0, sizeof(my_iptable));					// find the index within the available "len" within the 

	if (num > rules_remaining) {
		printk(KERN_INFO "minifw: minifw_table is out of memory. Will exit now..\n");
		return -ENOSPC;
	} 
	
	if (copy_from_user(my_ipt, buff, len)) {		// is the buffer copying from /proc/minifw successful, returns 0 on success
		printk(KERN_INFO "Sorry, reading the user-data from /proc failed");
		return -EFAULT;
	}					
	//printk(KERN_INFO "\ncopied the rule from user \nrules_remaining: %d, num: %d, len: %ld\n", rules_remaining, num, len);

	// check the access rights of the user
	if(Check_Permission(my_ipt)) {
		printk(KERN_INFO "minifw: %d UID doesn't have sufficient rights to access minifw\n", current->uid);
		return -EFAULT;	
	}
	
	// check the action to be taken: either delete OR block / unblock OR allow_access / remove_access. Too much action :-)
	if(my_ipt->action == DELETE) {
		if (!Delete_Rule(my_ipt))
			printk(KERN_INFO "minifw: minifw has deleted the rule %u\n", my_ipt->rule_index);		
		else
			printk(KERN_INFO "minifw: minifw couldn't find your rule to delete\n");		
		return 0;
	}
	// users who aren't super-user shouldn't be able to change the access rights of minifw
	else if(my_ipt->action == ALLOW_ACCESS) {
		if (current->uid != 0)
			printk(KERN_INFO "minifw: only the super user can change the access permissions\n");
		else {			
			printk(KERN_INFO "minifw: UID %d gained access rights\n", my_ipt->uid);
			allowed_users[(my_ipt->uid % UID_MAX)] = 1;	
			//printk(KERN_INFO "allowed_users[%d] = 1", my_ipt->uid % UID_MAX);
		}
		return 0;
	}
	else if(my_ipt->action == REMOVE_ACCESS) {
		if (current->uid != 0)
			printk(KERN_INFO "minifw: only the super user can change the access permissions\n");
		else {			
			if (my_ipt->uid == 0)		// the super user shouldn't be able to remove his own right
				return 0;
			allowed_users[(my_ipt->uid % UID_MAX)] = 0;
		}
		return 0;
	}

	//printk(KERN_INFO "my_ipt hook number: %u \n", my_ipt->hook_entry)
	memcpy(minifw_rules_table + rule_index, my_ipt, sizeof(my_iptable));
	//printk(KERN_INFO "rule written. rule_index: %d, num_of_rules: %d", rule_index+1, num_of_rules+1);
	rule_index ++;
	num_of_rules ++;
	
	return len;	
}

int minifw_read(char *page, char **start, off_t off, int count, int *eof, void *data) {
	int len;
	printk(KERN_INFO "minifw: Total number of rules: %d\n", num_of_rules);

	len = sizeof(my_iptable);
	if (!num_of_rules) {
		memset(my_ipt, 0, len);
		memcpy(page, my_ipt, len);
		return 0;
	} 	
	memcpy(my_ipt, minifw_rules_table + next_rule_ctr, len);				// copy the rule at next_rule_ctr to my_ipt struct,
	my_ipt->rule_index = next_rule_ctr;										// will be passed to user-space read through "page" buffer

	if (next_rule_ctr >= num_of_rules - 1) {
		//printk(KERN_INFO "This is the last rule in minifw_rules_table, next_rule_ctr: %d", next_rule_ctr);
		my_ipt->action |= IS_LAST_RULE;
	}	
	//printk("my_ipt->rule_index: %c, my_ipt->hook_entry: %c, my_ipt->action: %c, my_ipt->packet_count: %ld, my_ipt->uid: %d\n", my_ipt->rule_index, my_ipt->hook_entry, my_ipt->action, my_ipt->packet_count, my_ipt->uid);
				
	memcpy(page, my_ipt, len);												// my_ipt struct copied to page buffer
	my_ipt->action &= (~IS_LAST_RULE);  	

	if (next_rule_ctr >= num_of_rules - 1)									// set the next_rule_ctr to 0 if it has touched the
		next_rule_ctr = 0;													// total num_of_rules in minifw_rules_table
	else	
		++next_rule_ctr;												
	return len;
}

// hook function for filtering inbound packets 
unsigned int minifw_inbound_filter(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in,
									const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	int index = 0;
	int action = 0;	
	for(index = 0; index < num_of_rules; index ++) {
		if(minifw_rules_table[index].hook_entry == NF_INET_LOCAL_IN) 
		{
			action = Check_Rule(skb, &minifw_rules_table[index]);
			if(!action)	{				
				if (minifw_rules_table[index].action == BLOCK)
					return NF_DROP;
				else
					return NF_ACCEPT;
			}			
		}	
	}
	return NF_ACCEPT;
}

// hook function for filtering outbound packets
unsigned int minifw_outbound_filter(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in,
									const struct net_device *out, int (*okfn)(struct sk_buff *)) 
{
	int index = 0;
	int action = 0;	
	for(index = 0; index < num_of_rules; index ++) {
		if(minifw_rules_table[index].hook_entry == NF_INET_LOCAL_OUT) {
			action = Check_Rule(skb, &minifw_rules_table[index]);
			if(!action) {				
				if (minifw_rules_table[index].action == BLOCK)
					return NF_DROP;
				else
					return NF_ACCEPT;
			}
		}	
	}
	return NF_ACCEPT;
}

// check for access right for the uid passed through my_ipt
int Check_Permission(const my_iptable *my_ipt) {	
	//printk(KERN_INFO "minifw: Checking the access right of UID %d, Index: %d\n", my_ipt->uid, my_ipt->uid % UID_MAX);
	if (allowed_users[(current->uid % UID_MAX)]) {	
		printk(KERN_INFO "minifw: UID %d is allowed to access minifw\n", my_ipt->uid);
		return 0;
	}
	else
		return 1;
}

// delete a rule from minifw policy set
int Delete_Rule(const my_iptable *my_ipt) {
	unsigned int index = my_ipt->rule_index - 1;
	if (index + 1 > num_of_rules) {
		printk(KERN_INFO "minifw: The index for the given rule is out of bounds, Delete operation unsuccessful\n");
		return 1;
	}
	memset(&(minifw_rules_table[index]), 0 , sizeof(my_iptable));	// set the bytes of the rule to null
		
	if (index == num_of_rules - 1) { 								// if the deleted rule was the last rule
		--num_of_rules;												// shall decrement the rule_index
		--rule_index;	
	}	
	else {															// if this rule wasn't the last rule, shift all the rules 
		for(; index < num_of_rules-1; index++)						// after the "deleted" rule to one position left in the minifw_rules_table
			minifw_rules_table[index] = minifw_rules_table[index + 1];		
		num_of_rules --;
		rule_index --;
	}
	return 0;
}

int Check_Rule(struct sk_buff *skb, my_iptable *my_ipt) {
	// initializing the IP packet's headers which are inside a union in sk_buff stucture
	//struct ethhdr *eth_h 	=	eth_hdr(skb);					
	struct iphdr *ip_header 		= 	ipip_hdr(skb);		// defined in /lib.../linux/ip.h, returns iphdr as (struct iphdr*)skb_network_header(skb)
	struct tcphdr *tcp_header 		=	tcp_hdr(skb);		// in /lib.../tcp.h, 	returns tcphdr as (struct tcphdr*)skb_transport_header(skb)
	struct udphdr *udp_header 		=	udp_hdr(skb);		// in /lib.../udp.h, 	returns udphdr as (struct udphdr*)skb_transport_header(skb)
	// struct icmphdr *icmp_header 	=	icmp_hdr(skb);		// in /lib/.../icmp.h, 	returns icmphdr as (struct icmphdr*)skb_transport_header(skb)
	
	// check the IP address field
	if((my_ipt->ip_rule.bitmask & IS_SIP) == IS_SIP) {
		if(!Check_IP((unsigned char *)(&ip_header->saddr), my_ipt->ip_rule.sip, my_ipt->ip_rule.smask, IS_SIP))
		{}
		else
			return RULE_DOES_NOT_MATCH;
	}
	if ((my_ipt->ip_rule.bitmask & IS_DIP ) == IS_DIP) {
		if(!Check_IP((unsigned char *)(&ip_header->daddr), my_ipt->ip_rule.dip, my_ipt->ip_rule.dmask, IS_DIP))
		{}
		else
			return RULE_DOES_NOT_MATCH;
	}	

	// check for tcp / udp /icmp protocols
	if ((my_ipt->ip_rule.bitmask & IP_TYPE_PACKET ) == IP_TYPE_PACKET)		// check the type of protocol if the packet is of type IP
	{		
		if (!Check_Protocol(ip_header->protocol, my_ipt->ip_rule.proto, IP_TYPE_PACKET))	// shall return success for ICMP protocol too as it is saved in my_ipt->ip_rule.proto
		{}
		else
			return RULE_DOES_NOT_MATCH;
	}
	
	// check for tcp / udp protocols through their port numbers OR any other port numbers
	if ((my_ipt->port_rule.bitmask & IS_SPORT) == IS_SPORT)	{
		if (!Check_Port(tcp_header->source, my_ipt->port_rule.sport, IS_SPORT))
		{}
		else if (!Check_Port(udp_header->source, my_ipt->port_rule.sport, IS_SPORT))
		{}
		// else if (!Check_Port(icmp_header->source, my_ipt->port_rule.sport, IS_SPORT))	// icmp header doesn't have a source/dest port
		// {}
		else
			return RULE_DOES_NOT_MATCH;  
	}
	if ((my_ipt->port_rule.bitmask & IS_DPORT) == IS_DPORT) {
		if (!Check_Port(tcp_header->dest, my_ipt->port_rule.dport, IS_DPORT))
		{printk(KERN_INFO "Destination port checking\n");}
		else if (!Check_Port(udp_header->dest, my_ipt->port_rule.dport, IS_DPORT))
		{}
		// else if (!Check_Port(icmp_header->source, my_ipt->port_rule.sport, IS_DPORT))
		// {}
		else
			return RULE_DOES_NOT_MATCH;  
	}

	my_ipt->packet_count++;			// increase the packet count under my_ipt and return RULE_MATCHES if the fields were properly set
	return RULE_MATCHES;
}

int Check_IP(const unsigned char *ip_addr1, const unsigned char *ip_addr2, const char *net_mask, const unsigned char bmask) {
	int action = RULE_DOES_NOT_MATCH;
	unsigned char accept_all_ip[] = {0x00,0x00,0x00,0x00};
	int *ip1, *ip2, *netmask;
	ip1 = (int *)ip_addr1,
	ip2 = (int *)ip_addr2;
	netmask = (int *)net_mask;
	
	do {
		if (!memcmp(ip1, ip2, IP_ADDR_LEN))	{					// check if the host-ip address is the same
			action = RULE_MATCHES;	
			break;
		}
		else {
			if(!memcmp(accept_all_ip, net_mask, IP_ADDR_LEN)) { 		// check if the subnet mask is 0.0.0.0, if so accept the packets
				action = RULE_MATCHES;
				break;
			}												
			else {				
				if(((*ip1)&(*netmask)) == ((*ip2)&(*netmask))) {   	// check if the net-address (host & mask) is same
					action = RULE_MATCHES;								
					break;
				}
				else {
					action = RULE_DOES_NOT_MATCH;							
					break;
				}
			}
		}
	}
	while(0)	;
	return action;
}			

int Check_Protocol(const unsigned short protocol1, const unsigned short protocol2, const unsigned char bmask) {
	int action = RULE_DOES_NOT_MATCH;
	do {		
		if(protocol2 == ALL_PROTOCOLS) {
			action = RULE_MATCHES;		
			break;
		}			
		else if(protocol1 == protocol2) {
			action = RULE_MATCHES;		
			break;
		}			
		else {
			action = RULE_DOES_NOT_MATCH;	
			break;
		}
	}
	while(0);
 	return action;				
}

int Check_Port(const unsigned short port1, const unsigned short port2, const unsigned char bmask) {
	int action = RULE_DOES_NOT_MATCH;	
	do {
		if(port1 == port2) {
			printk(KERN_INFO "Destination port matches\n");
			action = RULE_MATCHES;					
			break;
		}
	else { 
		action = RULE_DOES_NOT_MATCH;			
		break;
		}
	}
	while(0);
	return action;
}

void cleanup_minifw_read_write_module(void) {
	remove_proc_entry("minifw", NULL);
	vfree(my_ipt);
	printk(KERN_INFO "minifw: minifw read_write module unloaded successfully\n");
}

void cleanup_rule_match_module(void) {
	nf_unregister_hook(&nfho_in);
	nf_unregister_hook(&nfho_out);
	printk(KERN_INFO "minifw: minifw rule match module unloaded\n");
}

void my_cleanup_module(void) {
	cleanup_minifw_read_write_module();
	cleanup_rule_match_module();
}

module_init(my_init_module);
module_exit(my_cleanup_module);
