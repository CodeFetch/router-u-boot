/*
 * Minimal DHCP server for uIP
 *
 * Copyright (C) 2019 Vincent Wiemann <vw@derowe.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef __MINIDHCPD_H__
#define __MINIDHCPD_H__



#define ETH_ALEN	6
#define DHCP_MSG_LEN	236
#define DHCP_CHADDR_LEN	16

#define DEBUG 1

#define STATE_INITIAL			0
#define STATE_SENDING			1
#define STATE_DHCP_DISCOVER		2
#define STATE_DHCP_REQUEST		3
#define STATE_DHCP_RELEASE		4
#define STATE_DHCP_DISCOVER_OVER	5

#define MDHCPD_OPTION_CONSEC_ADDR		1	/* 0 = distributed/hashed IPs, 1 = consecutive */


typedef u16_t uip_ipaddr_t[2];

typedef struct {
	u8_t dest[ETH_ALEN];
	u8_t src[ETH_ALEN];
	u16_t type;
} mdhcpd_eth_hdr_t;

/* Holds the uIP UDP APP state */
typedef struct {
  char state;
  struct uip_udp_conn *conn;
  u16_t ticks;
  u8_t mac_addr[16];
  int mac_len;
} uip_udp_appstate_t;


/*ADDITION*/
typedef struct dhcp_client dhcp_client_t;
struct dhcp_client {
	u8_t state;
 	u32 ipaddr;
 	u8_t hwaddr[ETH_ALEN];
 	u8_t chaddr[DHCP_CHADDR_LEN];
	struct dhcp_client *next;
};

/* Holds all DHCP option's we're interested in */
struct dhcp_options {
	u8_t state;		/* e.g. DHCP_REQUEST*/
	u8_t options;		/* 1=Unicast */
	u8_t mac_addr[6];	/* MAC address of the client */
	u32 xid;		/* Transaction ID */
	u32 serverid;		/* ID of a server */
	u32 leasetime;	/* Lease time */
	u32 ipaddr;		/* IP address offered */
	u32 netmask;		/* Netmask */
	u32 dnsaddr;		/* DNS IP address */
	u32 default_router;	/* Default router */
};

/* Holds a minidhcpd instance */
typedef struct {
	uip_udp_appstate_t appstate;
	struct dhcp_options opt;
	u32 xid;
	u32 serverid;
	u32 leasetime;		/* Lease time given to clients */
	u32 ipaddr;			/* IP address of the DHCP server */
	u32 netmask;			/* Netmask of the network */
	u32 pool_start;		/* Start address of the IP address lease pool */
	u32 pool_end;			/* End address of the IP address lease pool */
	u32 dnsaddr;			/* DNS server IP address given to clients */
	u32 default_router;		/* Default router given to clients */
	u8_t hwaddr[ETH_ALEN];		/* Ethernet address of the DHCP server */
	u8_t options;			/* see definitions above */
	u32 next_ipaddr;		/* The next free IP address in consecutive mode */
	u8_t bitmap_size;		/* Size of the bitmap in bytes */
 	u8_t *pool_bitmap;		/* Set bits in the map represent client entries */
	dhcp_client_t *client_head;	/* Pointer to the first client added */
} minidhcpd_instance_t;

/* Initializes and configures the DHCP server */
int minidhcpd_init(void);

/* Called by uIP whenever there is a new UDP packet */
void minidhcpd_udp_appcall(void);
#define UIP_UDP_APPCALL minidhcpd_udp_appcall


#endif
