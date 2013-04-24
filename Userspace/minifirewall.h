/* header for minifirewall */

#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <netinet/in.h>

// defines for values of the arguments passed
#define INBOUND         0
#define OUTBOUND        1

#define SRC_IPADDR      2
#define DEST_IPADDR     3
#define SRC_NET_MASK    4
#define DEST_NET_MASK   5
#define SRC_PORT        6
#define DEST_PORT       7
#define PROTOCOL        8

#define ACTION          9
#define BLOCK           10
#define UNBLOCK         11

#define DELETE          12
#define PRINT           13

#define PERMIT          14
#define ALLOW_ACCESS    15
#define REMOVE_ACCESS   16

#define MAX_NUM_OF_RULES        256             // one word length to store the rule number
#define IS_LAST_RULE            0x80            // MSB bit to denote the last rule

#define UID_MAX                 256


// Netfilter hooks
#define NF_IP_PRE_ROUTING       0
#define NF_IP_LOCAL_IN          1
#define NF_IP_FORWARD           2
#define NF_IP_LOCAL_OUT         3
#define NF_IP_POST_ROUTING      4

// defines for determining the protocols and their header lengths
// some are taken from netinet/if_ether.h
#ifndef IP_ADDR_LEN
#define IP_ADDR_LEN             4                       // 4 bytes for IPv4 address
#endif

// valuea taken from net/ethernet.h
#ifndef IP_PROTOCOL 
#define IP_PROTOCOL     0x800                               // ETHERTYPE_IP
#endif

// following values taken from netinet/in.h
#ifndef TCP_PROTOCOL
#define TCP_PROTOCOL    0x06                                 // IPPROTO_TCP
#endif

#ifndef UDP_PROTOCOL
#define UDP_PROTOCOL    0x11                                 // IPPROTO_UDP
#endif

#ifndef ICMP_PROTOCOL
#define ICMP_PROTOCOL   0x01                                 // IPPROTO_ICMP
#endif

// byte value for all protocols
#define ALL_PROTOCOLS   0xFF
#define IP_TYPE_PACKET  0x04


typedef struct port_rule{
        unsigned char  bitmask;                 // to distinguish source port from destination port
        unsigned short sport;
        unsigned short dport;
#define IS_SPORT 0x01
#define IS_DPORT 0x02
}my_port_rule;

typedef struct ip_rule{
        unsigned char  bitmask;                 // to distinguish source ip from destination ip
        unsigned char  sip[IP_ADDR_LEN];
        unsigned char  smask[IP_ADDR_LEN];
        unsigned char  dip[IP_ADDR_LEN];
        unsigned char  dmask[IP_ADDR_LEN];
        unsigned char  proto;                   //can be tcp/udp/icmp
#define IS_SIP 0x01
#define IS_DIP 0x02
#define IS_SMASK 0x10
#define IS_DMASK 0x20
}my_ip_rule;


// need a structure to pass the arguments to the kernel space through the write() system call
typedef struct my_ipt{        
        my_port_rule    port_rule;
        my_ip_rule      ip_rule;        
        unsigned char   hook_entry;
        unsigned char   rule_index;
        unsigned char   action;
        unsigned long   packet_count;
        unsigned int    uid;    
        unsigned short  dummy_byte;
}my_iptable;





