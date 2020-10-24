/*
 * minidhcpd - Embedded DHCP server
 *
 * Copyright (C) 2019 Vincent Wiemann <vw@derowe.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include "uip.h"
#include "uip_arp.h"
#include "minidhcpd.h"
#include "minidhcp.h"

#define debug_printf(fmt, ...) \
            do { if (DEBUG) printf("minidhcpd: "fmt, ##__VA_ARGS__); } while (0)

static minidhcpd_instance_t *mdhcpd = NULL;

/**
 * uip_htonl() - Convert an u32 from host to network byte order
 * @n: u32 in host byte order
 *
 * Note: Works on little- and big-endian machines only
 *
 * Return: n in network byte order
 */
u32 uip_htonl(u32 n) {
	unsigned int i = 1;  
	char *c = (char *)&i;

	if (*c)
		return ((n & 0xff) << 24) |
				((n & 0xff00) << 8) |
				((n & 0xff0000UL) >> 8) |
				((n & 0xff000000UL) >> 24);

	return n;
}

/**
 * uip_htons() - Convert an u16_t from host to network byte order
 * @n: u16_t in host byte order
 *
 * Note: Works on little- and big-endian machines only
 *
 * Return: n in network byte order
 */
u16_t uip_htons(u16_t n) {
	unsigned int i = 1;  
	char *c = (char *)&i;

	if (*c)
		return (((n >> 8) & 0xff) | ((n & 0xff) << 8));

	return n;
}

/**
 * uip_ntohl() - Convert an u32 from network to host byte order.
 * @n: u32 in network byte order
 *
 * Note: Works on little- and big-endian machines only
 *
 * Return: n in host byte order
 */
u32 uip_ntohl(u32 n) {
	return uip_htonl(n);
}

/**
 * uip_ntohs() - Convert an u16_t from network to host byte order.
 * @n: u16_t in network byte order
 *
 * Note: Works on little- and big-endian machines only
 *
 * Return: n in host byte order
 */
u16_t uip_ntohs(u16_t n) {
	return uip_htons(n);
}

/**
 * str_mac() - Converts a MAC address to a human-readable string
 * @hwaddr: pointer to the MAC address
 *
 * Return: pointer to the MAC address string
 */
char *str_mac(u8_t *hwaddr) {
	static char str[18];

	sprintf(str, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
	    hwaddr[0], hwaddr[1], hwaddr[2],
	    hwaddr[3], hwaddr[4], hwaddr[5]);

	return str;
}

/**
 * str_ip() - Converts an IPv4 address to a human-readable string
 * @ipaddr: the IPv4 address
 *
 * Return: pointer to the IP address string
 */
char *str_ip(const u32 ipaddr) {
	static char str[16];
  	u8_t *bytes = (u8_t *)&ipaddr;

	sprintf(str, "%d.%d.%d.%d",
            bytes[0], bytes[1], bytes[2], bytes[3]);

	return str;
}

/**
 * aton() - Parses an IP address string to a u32 in network byte order
 * @ipstr: points to the beginning of the string
 *
 * Note: Does not check the input
 *
 * Return: an u32 integer representing the IP
 */
u32 aton(char *ipstr) {
	char *buf = ipstr;
	int b = 0, c = 0, value = 0;
	u8_t ip[4];

	while(b < 4 && c < 5 && ((*buf >= '0' && *buf <= '9') || *buf == '.')) {
		if(c == 4 || *buf == '.') {
			if(value < 256)
				ip[b] = (u8_t)value;
			value = 0;
			b++;
			c++;
			buf++;
		} else {
			value = value * 10 + *(buf++) - '0';
			c++;
		}
	}

	return *(u32 *)&ip;
}

int ip_range_valid(minidhcpd_instance_t *m, u32 ipaddr) {
	if(ipaddr < m->pool_start || ipaddr > m->pool_end)
		return 0;
	return 1;
}

/**
 * client_add() - Adds a new client entry
 * @m: Points to the minidhcpd instance
 * @hwaddr: Points to the hardware address
 *
 * Return: Pointer to the client entry on success, NULL pointer otherwise
 */
dhcp_client_t *client_add(minidhcpd_instance_t *m, u8_t *hwaddr, u8_t *chaddr, u32 ipaddr) {
	dhcp_client_t *new_client;

	new_client = (dhcp_client_t *)malloc(sizeof(dhcp_client_t));

	if (!new_client) {
		printf_err("minidhcpd: Failed to allocate a new client entry");
		return NULL;
	}

	if(hwaddr)
		memcpy(new_client->hwaddr, hwaddr, ETH_ALEN);

	if(chaddr)
		memcpy(new_client->chaddr, chaddr, DHCP_CHADDR_LEN);

	new_client->ipaddr = ipaddr;
	new_client->next = m->client_head;
	m->client_head = new_client;

	debug_printf("allocated client %s [CHADDR %s] %s\n", str_mac(hwaddr), str_mac(chaddr), str_ip(ipaddr));

	return new_client;
}

/**
 * ip_bitmap_get() - Gets the IP pool bit of an IP address
 * @m: Points to the minidhcpd instance
 * @ipaddr: The IP address
 *
 * Return: the bit's value in the pool bitmap of an IP address
 */
static u8_t ip_bitmap_get(minidhcpd_instance_t *m, u32 ipaddr) {
	u32 ipdiff = ipaddr - m->pool_start; 
	u8_t offset = ipdiff / 8;

	if(offset > m->bitmap_size) {
		debug_printf("IP not in range %s\n", str_ip(ipaddr));
		return 0;
	}

	return ((1 << (ipdiff % 8)) & *(u8_t *)(m->pool_bitmap + offset)) ? 1 : 0;
}

/**
 * ip_bitmap_set() - Sets the bit in the IP pool bitmap of an IP address
 * @m: Points to the minidhcpd instance
 * @ipaddr: The IP address
 */
static void ip_bitmap_set(minidhcpd_instance_t *m, u32 ipaddr, u8_t val) {
	u32 ipdiff = ipaddr - m->pool_start; 
	u8_t offset = ipdiff / 8;

	if(offset > m->bitmap_size) {
		debug_printf("IP not in range %s\n", str_ip(ipaddr));
		return;
	}

	if(val) {
		*(u8_t *)(m->pool_bitmap + offset) |= 1 << (ipdiff % 8);
	} else {
		*(u8_t *)(m->pool_bitmap + offset) &= ~(1 << (ipdiff % 8));
	}
}

/**
 * find_free_ipaddr() - Finds a free IP address
 * @m: Points to minidhcpd instance
 * @chaddr: Points to the hardware address
 *
 * Return: IP address if found, 0 otherwise
 */
static u32 find_free_ipaddr(minidhcpd_instance_t *m, u8_t *chaddr) {
	u32 ipaddr, startaddr;
	u32 hash;
	int i;

	if ((m->options & MDHCPD_OPTION_CONSEC_ADDR) == MDHCPD_OPTION_CONSEC_ADDR)
		/* Start with the next unused IP address */
		ipaddr = m->next_ipaddr;
	else {
		/* Start with an IP address hashed from the client's hardware address */ 
		for (hash = 0, i = 0; i < ETH_ALEN; i++)
			hash = chaddr[i] + (hash << 6) + (hash << 16) - hash;

		ipaddr = m->pool_start + hash % (1 + m->pool_end - m->pool_start);
	} 

	startaddr = ipaddr;

	do {
		/* Return the IP address if an entry with this IP address does not exist
		 * (filters out IP addresses which are buggy on some ⊞ systems)
		 */ 
		if(!ip_bitmap_get(m, ipaddr) &&
		    ((ipaddr & 0xe0000000) != 0xc0000000 ||
		    ((ipaddr & 0xff) != 0xff && (ipaddr & 0xff) != 0x0))) {
			m->next_ipaddr = ipaddr + 1;
			return ipaddr;
		}

		ipaddr++;

		if(ipaddr > m->pool_end) {
			ipaddr = m->pool_start;
		}

	} while (ipaddr != startaddr);

	return 0;
}

/**
 * client_find_by_ipaddr() - Finds a client entry by its IP address
 * @m: Points to the minidhcpd instance
 * @ipaddr: The IP address
 *
 * Return: Pointer to client entry if found, NULL pointer otherwise
 */
dhcp_client_t *client_find_by_ipaddr(minidhcpd_instance_t *m, u32 ipaddr) {
	dhcp_client_t *client = m->client_head;

	/* Check if the corresponding bit is set in the IP pool bitmap */
	if(!ip_bitmap_get(m, ipaddr)) {
		debug_printf("no client matching IP address %s found in bitmap\n", str_ip(ipaddr));
		return NULL;
	}

	while(client && client->ipaddr != ipaddr)
		client = client->next;

	if(!client) {
		debug_printf("no client matching IP address %s found\n", str_ip(ipaddr));
		return NULL;
	}

	debug_printf("found client matching IP address %s: \n", str_ip(ipaddr));

	return client;
}

/**
 * client_find_by_hwaddr() - Finds a client entry by its hardware address
 * @head: Points to the head of the client list
 * @hwaddr: Points to the hardware address
 *
 * Return: Pointer to the client entry if found, NULL pointer otherwise
 */
dhcp_client_t *client_find_by_hwaddr(dhcp_client_t *head, u8_t *hwaddr) {
	dhcp_client_t *client = head;

	while(client && memcmp(client->hwaddr, hwaddr, ETH_ALEN))
		client = client->next;

	if(!client) {
		debug_printf("could not find a client matching hardware address %s\n",
		    str_mac(hwaddr));

		return NULL;
	}

	debug_printf("found a client matching hardware address %s: %s\n",
	    str_mac(hwaddr), str_ip(client->ipaddr));

	return client;
}

/**
 * client_find_by_chaddr() - Finds client entry by its DHCP HW address
 * @head: Points to head of client list
 * @chaddr: Points to the hardware address
 *
 * Return: Pointer to client entry if found, NULL pointer otherwise
 */
dhcp_client_t *client_find_by_chaddr(dhcp_client_t *head, u8_t *chaddr) {
	dhcp_client_t *client = head;

	while(client && memcmp(client->chaddr, chaddr, DHCP_CHADDR_LEN))
		client = client->next;

	if(client) {
		debug_printf("found a client matching DHCP HW address: %s\n",
		    str_ip(client->ipaddr));
		return client;
	}

	debug_printf("could not find a client matching DHCP HW address\n");

	return NULL;
}

/**
 * client_get_instance() - Finds an existing client entry or otherwise creates a new one
 * @m: Points to the minidhcpd instance
 * @chaddr: Points to the hardware address
 *
 * Return: Pointer to client entry if found, NULL pointer otherwise
 */
dhcp_client_t *client_get_instance(minidhcpd_instance_t *m, u8_t *hwaddr, u8_t *chaddr) {
	dhcp_client_t *client = client_find_by_chaddr(m->client_head, chaddr);

	if((!client && !(client = client_add(m, hwaddr, chaddr, 0))) ||
	   (!(client->ipaddr = find_free_ipaddr(m, (u8_t *)&client->chaddr))))
		return NULL;

	return client;
}

/**
 * add_dhcp_option() - Adds DHCP option field to buffer.
 * @buf: Pointer to end of option buffer
 * @type: DHCP option type
 * @value: Pointer to field data
 * @length: Length of field data
 *
 * Return: Pointer to new end of option buffer
 */
static u8_t *add_dhcp_option(u8_t *buf, u8_t type, u8_t *value, u8_t length) {
	*buf++ = type;

	if(!value)
		return buf;

	*buf++ = length;
	memcpy(buf, value, length);

	return buf + length;
}

/**
 * add_dhcp_option_u32() - Adds a u32 DHCP option field to the buffer
 * @buf: Pointer to end of option buffer
 * @type: DHCP option type
 * @value: field data
 *
 * Return: Pointer to the end of the option buffer
 */
static u8_t *add_dhcp_option_u32(u8_t *buf, u8_t type, u32 value) {
	u32 val = htonl(value);

	return add_dhcp_option(buf, type, (u8_t *)&val, 4);
}

/**
 * handle_request() - Handles a DHCP REQUEST packet
 * @m: Points to the minidhcpd instance
 */
static void handle_request(minidhcpd_instance_t *m) {
	dhcp_msg_t *msg = (dhcp_msg_t *)uip_appdata;
	mdhcpd_eth_hdr_t *hdr = (mdhcpd_eth_hdr_t *)&uip_buf[0];
	dhcp_client_t *client = NULL;
	u8_t *buf, mtype = DHCP_NAK,
	     *chaddr = msg->chaddr,
	     *hwaddr = hdr->src;

	if(m->opt.serverid && m->opt.serverid != m->serverid) {
		/* TODO: non-authoritative */
		debug_printf("[CHADDR %s] accepted a lease from another DHCP server %s %s which offered the IP %s\n", str_mac(hwaddr), str_mac(chaddr), str_ip(m->opt.serverid), str_ip(m->opt.ipaddr));
		return;
	}

	/* Change the BOOTP operation */
	msg->op = BOOTREPLY;

	/* Check if an offer was sent before */
 	client = client_find_by_chaddr(m->client_head, chaddr);

	if(!ip_range_valid(m, m->opt.ipaddr)) {
		debug_printf("requested IP address %s not in range", str_ip(m->opt.ipaddr));
	} else if(m->opt.default_router && m->opt.default_router != m->default_router) {
		debug_printf("default router %s in lease requested by %s [CHADDR %s] does not match\n", str_ip(m->opt.default_router), str_mac(hwaddr), str_mac(chaddr));
	} else if(m->opt.leasetime > m->leasetime) {
		debug_printf("lease time of %ds in lease requested by %s [CHADDR %s] is too long\n", m->opt.leasetime, str_mac(hwaddr), str_mac(chaddr));
	} else if(m->opt.netmask && m->opt.netmask != m->netmask) {
		debug_printf("netmask %s in lease requested by %s [CHADDR %s] does not match\n", str_ip(m->opt.netmask), str_mac(hwaddr), str_mac(chaddr));
	} else if(m->opt.dnsaddr && m->opt.dnsaddr != m->dnsaddr) {
		debug_printf("DNS address %s in lease requested by %s [CHADDR %s] does not match\n", str_ip(m->opt.dnsaddr), str_mac(hwaddr), str_mac(chaddr));
	} else if(ip_bitmap_get(m, ntohl(m->opt.ipaddr)) && (!client || client->ipaddr != m->opt.ipaddr || client->state != STATE_DHCP_REQUEST)) {
		if(!client) {
			debug_printf("IP address requested by %s (without a DISCOVER) was requested successfully by another client before\n", str_ip(m->opt.ipaddr));
		} else {
			if(client->ipaddr == m->opt.ipaddr) {
				switch(client->state) {
					case STATE_DHCP_RELEASE:
						debug_printf("%s formerly released by %s [CHADDR %s] was requested again, but is in use by another client now\n", str_mac(hwaddr), str_mac(chaddr), str_ip(m->opt.ipaddr));
						break;
					case STATE_DHCP_DISCOVER:
						debug_printf("lease requested by %s was requested successfully by another IP address (race condition)\n", str_ip(m->opt.ipaddr));
						break;/*TODO IF THE CLIENT ALREADY ACQUIRED A LEASE, FREE THE OLD ONE*/
				}
			} else {
				if(client->state == STATE_DHCP_REQUEST) {
					debug_printf("notice: %s [CHADDR %s] requested an IP address %s which differs from its existing lease's (%s) and", str_mac(hwaddr), str_mac(chaddr), str_ip(m->opt.ipaddr), str_ip(client->ipaddr));
				}

				debug_printf("%s [CHADDR %s] requested %s, but it is already in use by another client\n", str_mac(hwaddr), str_mac(chaddr), str_ip(m->opt.ipaddr));
			}
		}
	} else {
		if(client && client->ipaddr != m->opt.ipaddr && client->state == STATE_DHCP_REQUEST) {
			debug_printf("[CHADDR %s] %s requested a new IP address %s - setting its old IP address %s available again\n", str_mac(hwaddr), str_mac(chaddr), str_ip(m->opt.ipaddr), str_ip(client->ipaddr));
			ip_bitmap_set(m, client->ipaddr, 0);
		}

		if(client || (client = client_add(m, hwaddr, chaddr, htonl(m->opt.ipaddr)))) {
			mtype = DHCP_ACK;

			if(client->ipaddr == m->opt.ipaddr && client->state == STATE_DHCP_REQUEST) {
				debug_printf("%s [CHADDR %s] requested its old IP address %s again\n", str_mac(hwaddr), str_mac(chaddr), str_ip(m->opt.ipaddr));
			} else {
				debug_printf("%s [CHADDR %s] requested the unused IP address %s\n", str_mac(hwaddr), str_mac(chaddr), str_ip(m->opt.ipaddr));
			}
		}
	}

	buf = add_dhcp_option(&msg->options[4], DHCP_OPTION_DHCP_MESSAGE_TYPE, &mtype, 1);
	buf = add_dhcp_option_u32(buf, DHCP_OPTION_SERVER_IDENTIFIER, m->ipaddr);

	if(mtype == DHCP_ACK) {
		debug_printf("Sending DHCPACK to %s\n", str_mac(chaddr));
		memcpy(msg->yiaddr, &client->ipaddr, sizeof(msg->yiaddr));
		buf = add_dhcp_option_u32(buf, DHCP_OPTION_ROUTER, m->default_router);
		buf = add_dhcp_option_u32(buf, DHCP_OPTION_DOMAIN_NAME_SERVER, m->dnsaddr);
		buf = add_dhcp_option_u32(buf, DHCP_OPTION_IP_ADDRESS_LEASE_TIME, m->leasetime);
		buf = add_dhcp_option_u32(buf, DHCP_OPTION_SUBNET_MASK, m->netmask);
	} else {
		debug_printf("Sending DHCPNAK to %s\n", str_mac(chaddr));
	}

	if((msg->flags & 1) == 0 && client && client->ipaddr) {
		/* Unicast */
		memcpy(uip_udp_conn->ripaddr, &client->ipaddr, 4);
		uip_arp_update((u16_t *)uip_udp_conn->ripaddr, (struct uip_eth_addr *)&hdr->src);
		debug_printf("Updated ARP entry %s - %s", str_ip(ntohl(*(u32 *)uip_udp_conn->ripaddr)), str_mac(hwaddr));
	} else {
		memset((u8_t *)&uip_udp_conn->ripaddr, 0xff, 4);
	}

	buf = add_dhcp_option(buf, DHCP_OPTION_END, NULL, 0);
	uip_send(uip_appdata, buf - (u8_t *)uip_appdata);
}

/**
 * handle_discover() - Handles a DISCOVER packet
 * @m: Points to minidhcpd instance
 *
 * Return: 1 on success, 0 on failure
 */
static int handle_discover(minidhcpd_instance_t *m) {
	u8_t *buf;
	u32 ipaddr = 0;
	dhcp_client_t *client = m->client_head;
	u8_t mtype = DHCP_OFFER;
	dhcp_msg_t *msg = (dhcp_msg_t *)uip_appdata;
	mdhcpd_eth_hdr_t *hdr = (mdhcpd_eth_hdr_t *)&uip_buf[0];

	client = client_find_by_chaddr(m->client_head, (u8_t *)&msg->chaddr);

	if(!client) {
		client = client_add(m, (u8_t *)&hdr->src, (u8_t *)&msg->chaddr, 0);

		if(!client)
			return 0;

		debug_printf("allocated client entry for %s\n", str_mac((u8_t *)&hdr->src));
	}

	if(m->opt.ipaddr && ip_range_valid(m, m->opt.ipaddr) && (!ip_bitmap_get(m, m->opt.ipaddr) || client->ipaddr == m->opt.ipaddr)) {
		if(client->ipaddr && client->ipaddr != m->opt.ipaddr) {
			/* Client requested a different IP address in the DISCOVER -> we ignore the wish until a REQUEST */
			debug_printf("client with IP address %s wished for the differing IP address %s in DISCOVER", str_ip(client->ipaddr), str_ip(m->opt.ipaddr));
		} else {
			/* the IP address the client wishes is free or already assigned to it */
			client->ipaddr = m->opt.ipaddr;
		}
	} else {
		client->ipaddr = find_free_ipaddr(m, (u8_t *)&client->chaddr);
	}

	if (!client->ipaddr) {
		debug_printf("no free IP address available\n");
		return 0;
	}

	client->state = STATE_DHCP_DISCOVER;
	msg->op = BOOTREPLY;
	ipaddr = htonl(client->ipaddr);
	memcpy(msg->yiaddr, &ipaddr, sizeof(msg->yiaddr));

	if((msg->flags & 1) == 0) {
		/* Unicast */
		memcpy((u8_t *)&uip_udp_conn->ripaddr, (u8_t *)&ipaddr, 4);
		uip_arp_update((u16_t *)&uip_udp_conn->ripaddr, (struct uip_eth_addr *)&hdr->src);
	} else {
		memset((u8_t *)&uip_udp_conn->ripaddr, 0xff, 4);
	}

	buf = add_dhcp_option(&msg->options[4], DHCP_OPTION_DHCP_MESSAGE_TYPE, &mtype, 1);
	buf = add_dhcp_option_u32(buf, DHCP_OPTION_SERVER_IDENTIFIER, m->ipaddr);
	buf = add_dhcp_option_u32(buf, DHCP_OPTION_ROUTER, m->default_router);
	buf = add_dhcp_option_u32(buf, DHCP_OPTION_DOMAIN_NAME_SERVER, m->dnsaddr);
	buf = add_dhcp_option_u32(buf, DHCP_OPTION_IP_ADDRESS_LEASE_TIME, m->leasetime);
	buf = add_dhcp_option_u32(buf, DHCP_OPTION_SUBNET_MASK, m->netmask);
	buf = add_dhcp_option(buf, DHCP_OPTION_END, NULL, 0);

	uip_send(uip_appdata, buf - (u8_t *)uip_appdata);

	return 1;	
}

/**
 * handle_release() - Handles a RELEASE packet
 * @m: Points to minidhcpd instance
 *
 * Return: 1 on success, 0 on failure
 */
static int handle_release(minidhcpd_instance_t *m) {
	dhcp_client_t *client = m->client_head;
	dhcp_msg_t *msg = (dhcp_msg_t *)uip_appdata;

	client = client_find_by_chaddr(m->client_head, (u8_t *)&msg->chaddr);

	if(!client)
		return 0;

	ip_bitmap_set(m, client->ipaddr, 0);

	/* Note: As to RFC2131 4.3.4 we SHOULD keep the client allocated */

	return 1;
}

/**
 * handle_inform() - Handles an INFORM packet
 * @m: Points to minidhcpd instance
 *
 * Return: 1 on success, 0 on failure
 */
static int handle_inform(minidhcpd_instance_t *m) {
	/* Note: This is unsupported at the moment and should only be received if the client
	was configured with a static IP address */
	printf_err("minidhcpd: received unsupported INFORM packet");
return 0;
}

/**
 * parse_dhcp_options() - Parses the DHCP option fields
 * @opt: points to the DHCP option store
 * @optptr: points to the end of the option buffer
 * @len: length of the packet in bytes
 *
 * Return: DHCP message type on success, 0 on failure
 */
static u8_t parse_dhcp_options(struct dhcp_options *opt, u8_t *optptr, int len) {
	u8_t *end = optptr + len;
	u8_t type = 0;

	while(optptr < end) {
		switch(*optptr) {
			case DHCP_OPTION_DHCP_MESSAGE_TYPE:
				type = *(optptr + 2);
				break;
			case DHCP_OPTION_SUBNET_MASK:
				memcpy(&opt->netmask, optptr + 2, 4);
				break;
			case DHCP_OPTION_ROUTER:

				debug_printf("ID%d.%d.%d.%d.%d.%dID", optptr[0], optptr[1], optptr[2], optptr[3], optptr[4], optptr[5]);
				memcpy(&opt->default_router, optptr + 2, 4);
				debug_printf("%s", str_ip(opt->default_router));
				break;
			case DHCP_OPTION_DOMAIN_NAME_SERVER:
				memcpy(&opt->dnsaddr, optptr + 2, 4);
/* TODO: DHCP_OPTION_DOMAIN_NAME */
				break;
			case DHCP_OPTION_REQUESTED_IP_ADDRESS:
				memcpy(&opt->ipaddr, optptr + 2, 4);
				break;
			case DHCP_OPTION_IP_ADDRESS_LEASE_TIME:
				memcpy(&opt->leasetime, optptr + 2, 4);
				break;
/* TODO: DHCP_OPTION_OPTION_OVERLOAD */
			case DHCP_OPTION_SERVER_IDENTIFIER:
				memcpy(&opt->serverid, optptr + 2, 4);
				break;
/* TODO: DHCP_OPTION_PARAMETER_REQUEST_LIST */
			case DHCP_OPTION_END:
				return type;
		}

		optptr += optptr[1] + 2;
	}

	return type;
}

/**
 * parse_dhcp_msg() - Parses a DHCP packet's message structure
 * @opt: points to the DHCP options
 *
 * Return: DHCP message type on success, 0 on failure
 */
u8_t parse_dhcp_msg(struct dhcp_options *opt) {
	dhcp_msg_t *msg = (dhcp_msg_t *)uip_appdata;
	mdhcpd_eth_hdr_t *hdr = (mdhcpd_eth_hdr_t *)&uip_buf[0];

	if(msg->op != BOOTREQUEST) {
		debug_printf("nothing to parse\n");
		return 0;
	} /* };-P */

	if(msg->hlen != ETH_ALEN) {
		debug_printf("unsupported hardware address length %d\n", msg->hlen);
		return 0;
	}

	if(memcmp((u8_t *)&hdr->src, (u8_t *)msg->chaddr, ETH_ALEN)) {
		debug_printf("MAC address does not match hardware address.\n");
	}

	if(msg->giaddr[0] || msg->giaddr[1] || msg->giaddr[2] || msg->giaddr[3]) {
		/* TODO: implement relay-agent support (reply to giaddr) */
		printf_err("unsupported: message has been relayed by %u.%u.%u.%u\n", msg->giaddr[0], msg->giaddr[1], msg->giaddr[2], msg->giaddr[3]);
		return 0;
	}

	return parse_dhcp_options(opt, &msg->options[4], uip_datalen());
}

/**
 * minidhcpd_udp_appcall() - Called by uIP whenever a packet arrives
 */
void minidhcpd_udp_appcall(void) {
	u16_t lport = uip_htons(uip_udp_conn->lport);

	if (lport != BOOTPSERVER || !uip_newdata()) {
		printf_err("minidhcpd: bad call with port %d\n", lport);
		return;
	}

	memset(&mdhcpd->opt, 0, sizeof(mdhcpd->opt));
	mdhcpd->opt.state = parse_dhcp_msg(&mdhcpd->opt);
	switch(mdhcpd->opt.state) {
		case DHCP_REQUEST:
			debug_printf("received a DHCPREQUEST\n");
			handle_request(mdhcpd);
			break;
		case DHCP_DISCOVER:
			debug_printf("received a DHCPDISCOVER\n");
			handle_discover(mdhcpd);
			break;
		case DHCP_RELEASE:
			handle_release(mdhcpd);
			break;
		case DHCP_INFORM:
			handle_inform(mdhcpd);
			break;
		default:
			printf_err("received an unsupported DHCP type %d packet\n", mdhcpd->opt.state);
			break;
	}
}

/**
 * minidhcpd_init() - Allocates and initializes an instance
 */
int minidhcpd_init() {
	uip_ipaddr_t lipaddr;
	uip_ipaddr_t netmask;
	
	debug_printf("initializing...\n");

	if(mdhcpd) {
		printf_err("minidhcpd: already running\n");
		return -1;
	}

	/* Allocate minidhcp instance */
	mdhcpd = (minidhcpd_instance_t *)malloc(sizeof(minidhcpd_instance_t));

	if(!mdhcpd) {
		printf_err("minidhcpd: allocating instance failed\n");
		return -1;
	}

	mdhcpd->client_head = NULL;
	mdhcpd->ipaddr = (192<<24) | (168<<16) | (1<<8) | (1);
	mdhcpd->serverid = mdhcpd->ipaddr; 
	mdhcpd->netmask = (255<<24) | (255<<16) | (255<<8) | (0);
	mdhcpd->dnsaddr = (192<<24) | (168<<16) | (1<<8) | (1);
	mdhcpd->default_router = (192<<24) | (168<<16) | (1<<8) | (1);
	mdhcpd->pool_start = (192<<24) | (168<<16) | (1<<8) | (100);
	mdhcpd->pool_end = (192<<24) | (168<<16) | (1<<8) | (200);
	mdhcpd->leasetime = 3600;

	mdhcpd->bitmap_size = ((mdhcpd->pool_end - mdhcpd->pool_start) / 8 + 1);
	mdhcpd->pool_bitmap = (u8_t *)malloc(mdhcpd->bitmap_size * sizeof(u8_t));

	if (!mdhcpd->pool_bitmap) {
		printf_err("minidhcpd: failed to allocate DHCP pool bitmap\n");
		return -1;
	}

	/* Listen to everything on UDP port 67 */
	uip_ipaddr(lipaddr, 255, 255, 255, 255);
	uip_ipaddr(netmask, 255, 255, 255, 0);
	uip_setnetmask(netmask);
	mdhcpd->appstate.conn = uip_udp_new((u16_t *)&lipaddr, uip_htons(BOOTPCLIENT));
	mdhcpd->appstate.conn->lport = uip_htons(BOOTPSERVER);

	if(!mdhcpd->appstate.conn) {
		/* TODO: Proper error messages */
		printf_err("minidhcpd: failed to bind on port %d\n", BOOTPSERVER);
		return 0;
	}

	mdhcpd->appstate.conn->lport = uip_htons(BOOTPSERVER);
	debug_printf("server inititialized\n");

	return 1;
}
