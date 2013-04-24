#include <stdio.h>
#include <stdlib.h>
#include <getopt.h> 	
#include <string.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/types.h>
// following headers contain info related to Internet packets, mainly IP related structures and some essential functions
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "minifirewall.h"


/* globals */
char option_string[] = {PROTOCOL,    	':', 	// ':' tells that its argument is needed, null character tells that its not needed
		    			SRC_IPADDR,  	':',
		    			DEST_IPADDR,  	':', 
		    			SRC_PORT, 		':', 
		    			DEST_PORT, 		':',
		    			SRC_NET_MASK, 	':',
		    			DEST_NET_MASK, 	':', 		    			
		    			ACTION,       	':',
		    			PERMIT,	  		':', 	
		    			DELETE,		  	':',		    				            				    			
		    			PRINT,   		'\0'
		    		}; 

int global_fd = 0;
int in_out_flag = INT_MAX;	// flag to check whether the rule is for inbound or outbound packets
char inbound[] = "in";
char outbound[] = "out";		    		

/* function headers */
void Convert_To_Lower_Case(const char *argv, char *str);
void Set_Hook_Entry(my_iptable* my_ipt, char* optarg);
void Set_IP(const char* optarg, unsigned char is_source, my_iptable* my_ipt);
void Set_Net_Mask(const char *optarg, unsigned char is_source, my_iptable *my_ipt);
void Set_Net_Mask(const char *optarg, unsigned char is_source, my_iptable *my_ipt);
void Set_Port(const char *optarg, unsigned char is_source, my_iptable *my_ipt);
void Set_Protocol(const char *optarg, my_iptable *my_ipt);
void Set_Action(const char *optarg, my_iptable *my_ipt);
void Parse_Rules(const my_iptable *my_ipt);
void Delete_Rule(const int *fd, const char *optarg, my_iptable *my_ipt);
void Permit_User(const int *fd, const char *optarg, const int optind, 
				const int argc, char *const argv[], my_iptable *my_ipt);
void Error_Handler(const int fd, my_iptable *my_ipt);
void Read_From_Proc(int *fd);


int main(int argc, char **argv) {
	const char* errstr;
	int opt;
	my_iptable *my_ipt = NULL;
	my_ipt = (my_iptable *)malloc(sizeof(my_iptable));
	memset(my_ipt, '\0', sizeof(my_iptable));	

	int fd = open("/proc/minifw", O_WRONLY | O_APPEND );
	if (fd < 0) {
		fprintf(stderr, "%s\n", "Error: in opening /proc/minifw file. Please check if it is registered in /proc\n");
		return 1;
	}	
	//printf("/proc/minifw successfully opened for writing\n");
				
	global_fd = fd;
	while(1) {
		static struct option long_options[] =					//fields: {name, has_arg, flag, val}
		{							
			{"out",			no_argument,		&in_out_flag, 1},
			{"in",			no_argument,		&in_out_flag, 0},				
			{"proto",		required_argument,	0,  PROTOCOL},	
			{"srcip",		required_argument,	0, 	SRC_IPADDR},
			{"destip",		required_argument, 	0,  DEST_IPADDR},
			{"srcport",		required_argument, 	0, 	SRC_PORT},
			{"destport",    required_argument, 	0, 	DEST_PORT},
			{"srcnetmask",	required_argument, 	0, 	SRC_NET_MASK},
			{"destnetmask",	required_argument, 	0, 	DEST_NET_MASK},
			{"action",		required_argument, 	0, 	ACTION},	
			{"permit",      required_argument, 	0,	PERMIT},
			{"delete",		required_argument,	0, 	DELETE},			
			{"print",		no_argument,		0,  PRINT},			
			{0, 0, 0, 0}			
		};		

		int option_index = 0;
		opt = getopt_long(argc, argv, option_string, long_options, &option_index);		

		if(opt == -1)
			break;

		switch(opt) {
			case 0:
				if(long_options[option_index].flag != 0)		// means that the in_out_flag has been set
					break;
				//printf ("option %s", long_options[option_index].name);
            	if(optarg)
            		//printf (" with arg %s", optarg);
            	printf ("\n");
            	break;
			case SRC_IPADDR:                            	// ip can be followed by /num to denote subnet mask
				Set_IP(optarg, IS_SIP, my_ipt);				// set source IP
				//printf("Source IP address set\n");
				break;
			case DEST_IPADDR:
				Set_IP(optarg, IS_DIP, my_ipt);				// set destination IP
				//printf("Destination IP address set\n");
				break;
			case SRC_NET_MASK:
				Set_Net_Mask(optarg, IS_SMASK, my_ipt);		// set source net mask
				//printf("Source net mask set\n");
				break;
			case DEST_NET_MASK:
				Set_Net_Mask(optarg, IS_DMASK, my_ipt);		// set desination net mask
				//printf("Destination net mask set\n");
				break;
			case SRC_PORT:
				Set_Port(optarg, IS_SPORT, my_ipt);			// set source port
				//printf("Source port set\n");
				break;
			case DEST_PORT:	
				Set_Port(optarg, IS_DPORT, my_ipt);			//set destination port
				//printf("Destination port set\n");
				break;
			case PROTOCOL:
				Set_Protocol(optarg, my_ipt);				// set protocol
				//printf("Protocol set\n");
				break;
			case ACTION:
				Set_Action(optarg, my_ipt);					// set the action to be taken on the chain
				//printf("Action set\n");
				break;
			case DELETE:
				Delete_Rule(&fd, optarg, my_ipt);			// delete a rule
				//printf("Delete option set\n");				
				write(fd, my_ipt, sizeof(my_iptable));
				return 0;			
			case PERMIT:
				Permit_User(&fd, optarg, optind, argc, argv, my_ipt);	// permit the user with a given ID to access the minifirewall table 
				//printf("Permission option set\n");
				close(fd);
				free(my_ipt);
			case PRINT:				
				Read_From_Proc(&fd);						// print all the rules of minifirewall
				//printf("Print option set\n");
				close(fd);
				free(my_ipt);
				return 0;        
        	default:
        		break;        		
		}		
	}

	if(in_out_flag == 0) {
		//printf("packet is inbound\n");
		Set_Hook_Entry(my_ipt, inbound);		
	}
	else if(in_out_flag == 1) {
		//printf("packet is outbound\n");
		Set_Hook_Entry(my_ipt, outbound);		
	}	
	else {
		printf("Error: direction(whether inbound or outbound) not specified\nSyntax: --in for inbound, --out for outbound\n");		
		//exit(EXIT_FAILURE);
	}
	
	// save the uid of the current user in my_ipt structure if any other arguments aren't given
	if(optind < argc) {
		printf("Non-option arguments: ");
		while(optind < argc) 
			printf("%s ", argv[optind++]);
		putchar('\n');
	}
	else {		
		my_ipt->uid = getuid();											
		write(fd, my_ipt, sizeof(my_iptable));					// write the structure (with our UID) into /proc/minifw 
	}	

	close(fd);
	free(my_ipt);
	return 0;
} 	

void Set_Hook_Entry(my_iptable* my_ipt, char* optarg) {	
	char* str = optarg;	
	if(!strcmp(str, inbound)) {
		//printf("Added NF_IP_LOCAL_IN hook to my_ipt\n");
		my_ipt->hook_entry = NF_IP_LOCAL_IN;
	}
	else if(!strcmp(str, outbound)) {
		//printf("Added NF_IP_LOCAL_OUT hook to my_ipt\n");
		my_ipt->hook_entry = NF_IP_LOCAL_OUT;
	}
	else {
		fprintf(stderr, "Bad Argument: should be either --in or --out\n");
		Error_Handler(global_fd, my_ipt);		
	}
	//printf("Hook entry set for this rule: %d\n", my_ipt->hook_entry);
	//free(str);	
	return;
}

void Set_IP(const char* optarg, unsigned char is_source, my_iptable* my_ipt) {
	struct in_addr *ip_addr = (struct in_addr *)malloc(sizeof(struct in_addr));	// IP address has this structure defined in in.h
	char* str = (char *)malloc(100 * sizeof(char));		// save sufficient space for the IP string	
	Convert_To_Lower_Case(optarg, str);

	if (!inet_aton(str, ip_addr)) {			// convert the host address string to binary data form, externally defined in arpa/inet.h
		fprintf(stderr, "Bad argument: Couldn't parse IP address\n");
		Error_Handler(global_fd, my_ipt);	
	}	

	if (is_source == IS_SIP) {
		memcpy(my_ipt->ip_rule.sip, (unsigned char *)ip_addr, IP_ADDR_LEN);
		my_ipt->ip_rule.bitmask |= IS_SIP; 		

	}
	else if (is_source == IS_DIP) {
		memcpy(my_ipt->ip_rule.dip, (unsigned char *)ip_addr, IP_ADDR_LEN);
		my_ipt->ip_rule.bitmask |= IS_DIP;			
	}
	else {
		fprintf(stderr, "Bad argument: in IP address\n");
		Error_Handler(global_fd, my_ipt);	
	}	
	free(str);
	free(ip_addr);
	return;
}

void Set_Net_Mask(const char *optarg, unsigned char is_source, my_iptable *my_ipt) {
	struct in_addr *netmask = (struct in_addr *)malloc(sizeof(struct in_addr));
	char* str1 = NULL;
	str1 = (char *)malloc(100 * sizeof(char));		// save sufficient space for the IP string	
	Convert_To_Lower_Case(optarg, str1);
	printf("netmask is: %s\n", str1);
	if(!inet_aton(str1, netmask)) {
		fprintf(stderr, "Bad argument: Couldn't parse net mask\n");
		Error_Handler(global_fd, my_ipt);	
	}
	// save the source/destination mask information in ip_rule's bitmask byte
	if(is_source == IS_SIP) {
		memcpy(my_ipt->ip_rule.smask, (unsigned char *)netmask, IP_ADDR_LEN);
		my_ipt->ip_rule.bitmask |= IS_SIP;
	}
	else if(is_source == IS_DIP) {
		memcpy(my_ipt->ip_rule.dmask, (unsigned char *)netmask, IP_ADDR_LEN);
		my_ipt->ip_rule.bitmask |= IS_DIP;
	}
	else {
		fprintf(stderr, "Bad argument: in net mask\n");
		Error_Handler(global_fd, my_ipt);	
	}
	return;
}

void Set_Port(const char *optarg, unsigned char is_source, my_iptable *my_ipt) {	
	unsigned short port = 0;	
	port = atoi(optarg);
	//printf("port number: %u\n", port);
		
	if (is_source == IS_SPORT) {
		my_ipt->port_rule.sport = port; 
		my_ipt->port_rule.bitmask |= IS_SPORT;		
	}
	else if (is_source == IS_DPORT) {
		my_ipt->port_rule.dport = port; 
		my_ipt->port_rule.bitmask |= IS_DPORT;
	}
	else {
		fprintf(stderr, "Bad argument: in port number\n");
		Error_Handler(global_fd, my_ipt);	
	}	
	return;
}

void Set_Protocol(const char *optarg, my_iptable *my_ipt) {
	unsigned char protocol = 0;
	char *str = (char *)malloc(100);	
	
	Convert_To_Lower_Case(optarg, str);
		
	if (!strcmp("tcp", str)) {
		my_ipt->ip_rule.proto = TCP_PROTOCOL;
		my_ipt->ip_rule.bitmask |= IP_TYPE_PACKET;
	}
	else if (!strcmp("udp", str)) {
		my_ipt->ip_rule.proto = UDP_PROTOCOL;
		my_ipt->ip_rule.bitmask |= IP_TYPE_PACKET;
	}
	else if (!strcmp("icmp", str)) {
		my_ipt->ip_rule.proto = ICMP_PROTOCOL;
		my_ipt->ip_rule.bitmask |= IP_TYPE_PACKET;
	}
	else if (!strcmp("all", str)) {
		my_ipt->ip_rule.proto = ALL_PROTOCOLS;
		my_ipt->ip_rule.bitmask |= IP_TYPE_PACKET;
	}		
	else {
		fprintf(stderr, "Bad argument: in protocol\n");
		Error_Handler(global_fd, my_ipt);	
	}	
	free(str);
	return;
}

void Set_Action(const char *optarg, my_iptable *my_ipt) {
	char* str = NULL;
	str = (char *)malloc(strlen(optarg)+1);
	Convert_To_Lower_Case(optarg, str);

	if(my_ipt->action != 0)
		my_ipt->action = 0;
	if(!strcmp("block", str))	
		my_ipt->action = my_ipt->action + BLOCK;
	else if (!strcmp("unblock", str)) 
		my_ipt->action = my_ipt->action + UNBLOCK;	
	else {
		fprintf(stderr, "Bad argument: in --action, should be BLOCK or UNBLOCK\n");
		Error_Handler(global_fd, my_ipt);
	}
	free(str);
	return;
}

void Read_From_Proc(int *fd) {
	int read_flag = 0, rule_count = 0;
	my_iptable *my_ipt = (my_iptable *)malloc(sizeof(my_iptable));
	my_iptable *dummy_table = (my_iptable *)malloc(sizeof(my_iptable));	
	memset(my_ipt, 0, sizeof(my_iptable));
	memset(dummy_table, 0, sizeof(my_iptable));

	if(close(*fd) < 0)					// close the /proc/minifw 's descriptor, exit if it fails.
		exit(EXIT_FAILURE);

	//printf("my_ipt as read from proc\n");
	//printf("my_ipt->rule_index: %d, my_ipt->hook_entry: %d, my_ipt->action: %d, my_ipt->packet_count: %ld, my_ipt->uid: %d\n", my_ipt->rule_index, my_ipt->hook_entry, my_ipt->action, my_ipt->packet_count, my_ipt->uid);

	while (!read_flag) {
		*fd = open("/proc/minifw", O_RDONLY);
		if (read(*fd, my_ipt, sizeof(my_iptable)) < 0) {
			fprintf(stderr, "Error reading /proc/minifw\n");
			read_flag = 1;
			close(*fd);
			break;
		} 		
		if(!memcmp(my_ipt, dummy_table, sizeof(my_iptable)) && rule_count == 0) {		// check if the rule-set is empty	
			printf("Empty rule set read from minifw\n");
			close(*fd);
			read_flag = 1;
			break;
		}		
		++rule_count ;
		printf("Rule %u: ", my_ipt->rule_index + 1);
						
		if((my_ipt->action & IS_LAST_RULE) == IS_LAST_RULE && rule_count != 0) {
		//	printf("This is the last rule that minifirewall is reading\n");
			read_flag = 1;
			// close(*fd);
			// break;
		}
		Parse_Rules(my_ipt);
		if (read_flag) {
			close(*fd);		
			break;
		}
		else
			//printf("There are more rules to be read\n");		
		if (close(*fd) < 0)		
			exit(EXIT_FAILURE);			
	}
	free(my_ipt);
	free(dummy_table);
	return;
}

void Parse_Rules(const my_iptable *my_ipt) {
	struct in_addr *ip_addr;	
	// parsing the direction of the rule: should be in or out	
	if (my_ipt->hook_entry == NF_IP_LOCAL_IN)	
		printf(" --in ");	
	else if (my_ipt->hook_entry == NF_IP_LOCAL_OUT)	
		printf(" --out ");	
	else {		
		fprintf(stderr, "minifirewall: Error: direction of the rule couldn't be read\n");		
		//printf("my_ipt->hook_entry returned: %u\n", my_ipt->hook_entry);
	}
	
	// parsing the ip header
	if ((my_ipt->ip_rule.bitmask & IS_SIP) == IS_SIP) {
		ip_addr = (struct in_addr *)(my_ipt->ip_rule.sip);
		printf("--srcip ");
		printf("%s ", inet_ntoa(*ip_addr));
	}
	if ((my_ipt->ip_rule.bitmask & IS_DIP) == IS_DIP) {
		ip_addr = (struct in_addr *)(my_ipt->ip_rule.dip);
		printf("--destip ");
		printf("%s ", inet_ntoa(*ip_addr));
	}

	// parsing the subnet mask
	if ((my_ipt->ip_rule.bitmask & IS_SMASK) == IS_SMASK) {
		ip_addr = (struct in_addr *)(my_ipt->ip_rule.smask);
		printf("--srcnetmask %s ", inet_ntoa(*ip_addr));
	}
	if ((my_ipt->ip_rule.bitmask & IS_DMASK) == IS_DMASK) {
		ip_addr = (struct in_addr *)(my_ipt->ip_rule.dmask);
		printf("--destnetmask %s ", inet_ntoa(*ip_addr));
	}
	
	// parsing the ip protocol
	if ((my_ipt->ip_rule.bitmask & IP_TYPE_PACKET) == IP_TYPE_PACKET) {		
		printf("--proto ");
		if (my_ipt->ip_rule.proto == TCP_PROTOCOL)
			printf("tcp ");
		else if (my_ipt->ip_rule.proto == UDP_PROTOCOL)
			printf("udp ");
		else if (my_ipt->ip_rule.proto == ICMP_PROTOCOL)
			printf("icmp ");
		else if (my_ipt->ip_rule.proto == ALL_PROTOCOLS)
			printf("all ");
		else
			fprintf(stderr, "minifirewall: protocol not supported\n");
	}

	// parsing the port number
	if ((my_ipt->port_rule.bitmask & IS_SPORT) == IS_SPORT) {
		printf("--srcport ");		
		printf("%u ", my_ipt->port_rule.sport);
	}	
	if ((my_ipt->port_rule.bitmask & IS_DPORT) == IS_DPORT) {
		printf("--destport ");		
		printf("%u ", my_ipt->port_rule.dport);
	}

	// parsing the action of the rule
	if ((my_ipt->action & (~IS_LAST_RULE))== BLOCK)
		printf("--action BLOCK \n");
	else if ((my_ipt->action & (~IS_LAST_RULE)) == UNBLOCK)
		printf("--action UNBLOCK \n");
	else
		fprintf(stderr, "minifirewall: Bad argument received in action\n");	

	return;
}

void Delete_Rule(const int *fd, const char *optarg, my_iptable *my_ipt) {
	int index = atoi(optarg);
	if (index < 0) {
		fprintf(stderr, "minifirewall: rule number must be greater than 0\n");
		return ;
	} 
	my_ipt->rule_index = index;
	my_ipt->action = DELETE;	
}

void Permit_User(const int *fd, const char *optarg, const int optind, const int argc, char *const argv[], my_iptable *my_ipt) {		
	int uid = 0;

	// check if the "not" bit is set
	if (!strcmp(optarg, "!")) {		
		if (argv[optind - 1][0] == '-' || (argv[optind - 1][0] == '!' && optind == argc)) {
			fprintf(stderr, "minifirewall: uid not specified\n");
			return ;
		}			
		if ((argc-1) > optind  &&  argv[optind + 1][0] != '-') {
			fprintf(stderr, "minifirewall: parameters out of bound\n");
			return ;		
		}		
		my_ipt->action = REMOVE_ACCESS;
		uid = atoi(argv[optind]);
	}
	else {
		my_ipt->action = ALLOW_ACCESS;
		uid = atoi(optarg);
	}
	
	if (uid < 0) {
		printf("minifirewall: Bad argument in UID. Must be greater than 0 \n");
		return;
	}	
	my_ipt->uid = (uid % UID_MAX);
	printf("access to minifw granted to uid: %d\n", uid);
	write(*fd, my_ipt, sizeof(my_iptable));
	return;
}
 
void Convert_To_Lower_Case(const char *argv, char *str) {		// Convert all upper-cased arguments to lower case for ease of comparison
	int length = strlen(argv);
	strncpy(str, argv, length);
	str[length] = '\0';
	while(*str != '\0') {
		*str = tolower(*str);
		str ++;
	}
	return;
}

void Error_Handler(const int fd, my_iptable *my_ipt) {
	if (close(fd) < 0)
		fprintf(stderr, "minifirewall: /proc/minifw couldn't be closed properly\n");
	free(my_ipt);
	exit(EXIT_FAILURE);	
}


