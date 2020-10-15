/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
* Method: find_longest_prefix_match(struct sr_instance *sr, 
* uint32_t ip_dst)
* Scope: Global
*
* This method is called whenever we want to find the longest prefix
* match between all of the entries in the router's routing table. It
* requires a destination ip address, and the router's routing table, and
* returns a pointer to the node in the routing table which is the best
* match, else NULL if none match on prefix.
*
*---------------------------------------------------------------------*/

struct sr_rt *find_longest_prefix_match(struct sr_instance *sr, 
uint32_t ip_dst) {
	printf("Reached find longest prefix match fn\n");
	sr_print_routing_table(sr);
	/* TODO: Implement this */
	struct sr_rt* cur_routing_entry = sr->routing_table;
	struct sr_rt *longest_match = NULL;
	while (cur_routing_entry != NULL) {

		uint32_t ip_dst_mask = ip_dst & cur_routing_entry->mask.s_addr;
		if (ip_dst_mask == (cur_routing_entry->mask.s_addr & 
			cur_routing_entry->gw.s_addr)){
			/*Match found*/
			printf("Match found\n");
			if (longest_match == NULL || cur_routing_entry->mask.s_addr > 
				longest_match->mask.s_addr){
					longest_match = cur_routing_entry;
				}
		}

		cur_routing_entry = cur_routing_entry->next;
	}
	if (longest_match){
		printf("The best match is:\n");
		sr_print_routing_entry(longest_match);
	}
	else {
		printf("No longest prefix match found\n");
	}
	return longest_match;
}

/*---------------------------------------------------------------------
* Method: add_ethernet_headers(struct sr_instance *sr, uint8_t 
* *packet, char *interface, unsigned char mac[6])
* Scope: Global
*
* This function takes a router instance pointer, packet which is
* already allocated memory for, name of receiving interface, and
* a pointer to the related arp_cache_entry's MAC address. It adds 
* ethernet headers to the given packet.
*
*--------------------------------------------------------------------*/
void add_ethernet_headers(struct sr_instance *sr, uint8_t 
*packet, char *interface, unsigned char mac[6]){

	printf("Reached add_ethernet_headers function\n");
	assert(sr);
	assert(packet);
	assert(interface);
	sr_ethernet_hdr_t *casted_packet = (sr_ethernet_hdr_t *)(packet);
	assert(casted_packet);

	casted_packet->ether_type = htons(ethertype_ip);
	memcpy(casted_packet->ether_dhost, (uint8_t*)mac, 6);

	/* Find the src address from the outgoing interface */
	struct sr_if *outgoing_interface = sr_get_interface(sr, interface);
	if (outgoing_interface == 0) {
		fprintf(stderr, "An error occurred; outgoing interface not found\n");
		return;
	}
	memcpy(casted_packet->ether_shost, (uint8_t*)outgoing_interface->addr, 6);
	return;
}
/*----------------------------------------------------------------------------
* Method: add_ip_headers(struct sr_instance *sr, uint8_t *packet, 
* uint8_t ip_src, uint8_t ip_dst, unsigned int len);
*
* This function takes a pre-allocated packet and adds ip information to it, 
* including src and destination ip addresses. Also puts in the default ip info
* and recalculates the checksum.
*
*---------------------------------------------------------------------------*/

void add_ip_headers(struct sr_instance *sr, uint8_t *packet, uint8_t ip_src,
uint8_t ip_dst, unsigned int len){
	assert(len >= sizeof(sr_ip_hdr_t));
	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*)packet;
	assert(ip_hdr);
	ip_hdr->ip_v = 0x04;
	ip_hdr->ip_hl = 0x05; /*TODO Check that this is the right value */
	ip_hdr->ip_tos = 0x00;
	ip_hdr->ip_len = htons(len); /*Length, including data e.g. ICMP hdr if present*/
	ip_hdr->ip_id = htons(0x00);
	ip_hdr->ip_off = htons(0x00);
	ip_hdr->ip_ttl = 64;
	ip_hdr->ip_p = 0x00;
	ip_hdr->ip_src = ip_src;
	ip_hdr->ip_dst = ip_dst;
	ip_hdr->ip_sum = 0; /*To prevent segfaults from uninitialized memory*/
	ip_hdr->ip_sum = cksum(packet, sizeof(sr_ip_hdr_t));
	return;

}

/*---------------------------------------------------------------------------
* Method: add_icmp_headers(struct sr_instance *sr, uint8_t type, uint8_t sum,
* uint8_t code, unsigned int len);
*
* This function takes a preallocated packet with length len, a router instance,
* and source/destination type/code information and fills the packet with info
* related to the icmp header. Also recalculates the icmp checksum.
*
*---------------------------------------------------------------------------*/

void add_icmp_headers(struct sr_instance *sr, uint8_t *packet, uint8_t type,
uint8_t code, unsigned int len){
	assert(len >= sizeof(struct sr_icmp_hdr));
	struct sr_icmp_hdr *icmp_hdr = (struct sr_icmp_hdr*)packet;
	assert(icmp_hdr);
	icmp_hdr->icmp_sum = 0; /*Init so no segfault for uninitialized memory */
	icmp_hdr->icmp_type = type;
	icmp_hdr->icmp_code = code;
	icmp_hdr->icmp_sum = cksum(packet, sizeof(struct sr_icmp_hdr));
	return;
}

/*---------------------------------------------------------------------
* Method: prepare_to_send_ip_req(struct sr_instance *sr, uint8_t
* *packet, unsigned int len, char *interface, struct sr_arpentry 
* *arp_cache_entry)
* Scope: Global
*
* This method is called to prepare an IP packet to be sent out, and 
* takes a pointer to the router *sr, the *packet which should only 
* contain the IP portion, the length of the packet, and the
* arp_cache_entry pointer which should contain the MAC address. It
* returns the updated packet, complete with ethernet headers with some
* information filled out.
*--------------------------------------------------------------------*/
uint8_t *prepare_to_send_ip_req(struct sr_instance *sr, uint8_t
*packet, unsigned int len, char *interface, struct sr_arpentry 
*arp_cache_entry){
	
	uint8_t *packet_with_ethernet = \
	(uint8_t*)malloc(len + sizeof(sr_ethernet_hdr_t));
	add_ethernet_headers(sr, packet_with_ethernet, interface, 
	arp_cache_entry->mac);
	/*Add the IP part to the end of the packet*/
	memcpy(packet_with_ethernet + sizeof(sr_ethernet_hdr_t), packet, len);
	return packet_with_ethernet;
}
/*---------------------------------------------------------------------
* Method: handle_ip_packet_to_be_sent_out(struct sr_instance *sr, 
* uint8_t *packet, unsigned int len, char *interface)
* Scope: Global
*
* This method is called whenever an IP packet needs to be sent out, and 
* performs the proper steps in order to prepare for this. The packet
* buffer should only contain the IP portion. The packet length len, name 
* of the receiving interface *interface, and object representing the 
* router *sr_instance must also be given.
*
* Note: The packet and name of the receiving interface's memory are
* handled in sr_vns_comm.c so they are not freed here
*
*---------------------------------------------------------------------*/

void handle_ip_packet_to_be_sent_out(struct sr_instance *sr, uint8_t 
*packet, unsigned int len, char *interface, uint8_t *packet_with_ethernet){
	printf("Reached the handle_ip_packet_to_be_sent_out fn\n");
	assert(sr);
	assert(packet);
	assert(interface);
	assert(len >= sizeof(sr_ip_hdr_t));
	sr_ethernet_hdr_t *ethernet_packet =\
		(sr_ethernet_hdr_t*)packet_with_ethernet;
	assert(packet_with_ethernet);
	sr_ip_hdr_t *ip_packet = (sr_ip_hdr_t*)(packet);
	assert(ip_packet);

	/* Make sure the packet is still alive before forwarding */
	ip_packet->ip_ttl -= 1;
	if (ip_packet->ip_ttl <= 0) {
		fprintf(stderr, "This packet has a TTL of 0; cannot send it\n");
		uint8_t *empty_packet = (uint8_t*)malloc(len +sizeof(sr_ethernet_hdr_t));
		assert(empty_packet);
		
		struct sr_if *outgoing_interface = sr_get_interface(sr, interface);
		if (outgoing_interface == NULL){
			fprintf(stderr, "Error outgoing interface not found\n");
			free(empty_packet);
			return;
		}
		sr_prep_and_send_icmp3_reply(sr, empty_packet, len + 
			sizeof(sr_ethernet_hdr_t), 
			interface, outgoing_interface->ip, ip_packet->ip_src,
			outgoing_interface->addr, ethernet_packet->ether_shost,
			0x11, 0x00);
		free(empty_packet);
		return;
	}

	/* Recompute checksum, since the TTL changed */
	ip_packet->ip_sum = 0; /*Set to 0 so it doesnt affect the real 
	calculation*/
	uint16_t calculated_checksum = cksum(packet, sizeof(sr_ip_hdr_t));
	ip_packet->ip_sum = calculated_checksum;
	/*TODO: make sure checksum is updated in packet as well as ip_packet*/
	
	/*Find best-match IP address for this packet*/
	struct sr_rt *best_match = find_longest_prefix_match(sr,
	ip_packet->ip_dst);
	if (best_match == NULL) {
		fprintf(stderr, "No best match found\n");
		struct sr_if *outgoing_interface = sr_get_interface(sr, interface);
		if (outgoing_interface == NULL){
		  fprintf(stderr, "Error outgoing interface not found\n");
		  return;
		}
		uint8_t *empty_packet = (uint8_t*)malloc(len +sizeof(sr_ethernet_hdr_t));
		assert(empty_packet);
		sr_prep_and_send_icmp3_reply(sr, empty_packet, len +
			sizeof(sr_ethernet_hdr_t), interface, outgoing_interface->ip, ip_packet->
				ip_src, outgoing_interface->addr, ethernet_packet->ether_shost, 0x03, 
				0x00);
		free(empty_packet);
		return;
	}

	/* Check ARP cache for MAC address corresponding to the next-hop IP*/
	struct sr_arpentry *arp_cache_entry = sr_arpcache_lookup(&(sr->cache), 
	best_match->gw.s_addr);/**/

	if (arp_cache_entry == NULL) { /* No MAC addr found; make ARP req */
		uint8_t *packet_with_ethernet = \
			(uint8_t*)malloc(len + sizeof(sr_ethernet_hdr_t));
		assert(packet_with_ethernet);
		unsigned char broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
		
		add_ethernet_headers(sr, packet_with_ethernet,
			best_match->interface,
			broadcast_mac);
		
		/*Add the IP part to the end of the packet*/
		memcpy(packet_with_ethernet + sizeof(sr_ethernet_hdr_t), packet, len);
		
		/*Add this request to the arpcache queued requests*/
		struct sr_arpreq *arp_req = sr_arpcache_queuereq(&(sr->cache),
			best_match->gw.s_addr, packet_with_ethernet, len + sizeof(sr_ethernet_hdr_t),
			best_match->interface);/**/
		
		/*free(packet_with_ethernet);*/
		if (arp_req == NULL){
			fprintf(stderr, "Error occurred; the arp_req returned from\
			starter code was NULL....\n");
			return;
		}
		printf("Handling the new ARP request now\n");
		/*Send out request for the MAC address*/
		sr_handle_arpreq(sr, arp_req);
	}
	else { /*MAC addr found; create and send IP request*/
		printf("Found MAC; sending IP request\n");
		uint8_t *new_packet = prepare_to_send_ip_req(sr, packet, len, 
		interface, arp_cache_entry);
		ip_packet->ip_sum = 0; /*Reset to 0 for consistency*/
		ip_packet->ip_sum = cksum(ip_packet, sizeof(sr_ip_hdr_t));

		struct sr_if *outgoing_interface = sr_get_interface(sr, interface);
		if (outgoing_interface == 0) {
			printf("An error occurred; outgoing interface not found when forwarding\
			the ip packet\n");
			return;
		}
		int status = sr_send_packet(sr, new_packet, len + 
		sizeof(sr_ethernet_hdr_t), interface);
		if (status != 0){
			printf("An error occurred when sending packet! Status %d\n", status);
		}
		else {
			printf("IP Packet sent out\n");
		}
		free(new_packet);
	}
}

/*---------------------------------------------------------------------------
* Method: add_icmp3_headers(struct sr_instance *sr, uint8_t type, uint8_t sum,
* uint8_t code, unsigned int len);
*
* This function takes a preallocated packet with length len, a router instance,
* and source/destination type/code information. It also takes the IP packet. It
* fills the preallocated packet with info related to the icmp3 header, with
* the data field being filled with part of the IP packet. Also recalculates 
* the icmp3 checksum.
*
*---------------------------------------------------------------------------*/
 
void add_icmp3_headers(struct sr_instance *sr, uint8_t *packet, uint8_t type,
uint8_t code, unsigned int len, uint8_t *ip_packet){
  assert(len >= sizeof(struct sr_icmp_t3_hdr));
  struct sr_icmp_t3_hdr *icmp3_hdr = (struct sr_icmp_t3_hdr*)packet;
  assert(icmp3_hdr);
  icmp3_hdr->icmp_sum = 0; /*Init so no segfault for uninitialized memory */
  icmp3_hdr->icmp_type = type;
  icmp3_hdr->icmp_code = code;
	icmp3_hdr->unused = 0x00;
	icmp3_hdr->next_mtu = 0x00;
	memcpy(icmp3_hdr->data, ip_packet, ICMP_DATA_SIZE);
	icmp3_hdr->icmp_sum  = 0;
  icmp3_hdr->icmp_sum = cksum(packet, sizeof(struct sr_icmp_t3_hdr));
  return;
}

/*----------------------------------------------------------------------
* Method: sr_prep_and_send_icmp3_reply(struct sr_instance *sr, 
* uint8_t *packet, unsigned int len, char *interface, uint32_t ip_src,
* uint32_t ip_dst, uint8_t ether_shost[ETHER_ADDR_LEN], uint8_t 
* ether_dhost[ETHER_ADDR_LEN], uint8_t type, uint8_t code);
*
* This method prepares and sends an icmp3 reply to the given destination,
* with the given type and code. The packet argument should be a pre-
* allocated space with enough room for ethernet, ip and ICMP3 headers.
*
*----------------------------------------------------------------------*/

void sr_prep_and_send_icmp3_reply(struct sr_instance *sr, 
uint8_t *packet, unsigned int len, char *interface, uint32_t ip_src,
uint32_t ip_dst, uint8_t ether_shost[ETHER_ADDR_LEN], uint8_t 
ether_dhost[ETHER_ADDR_LEN], uint8_t type, uint8_t code){

	assert(packet);
	unsigned int min_total_len = sizeof(sr_ethernet_hdr_t) + sizeof(
	  sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
	unsigned int icmp3_offset = sizeof(sr_ethernet_hdr_t) + sizeof(
		sr_ip_hdr_t);
	unsigned int ip_offset = sizeof(sr_ethernet_hdr_t);
	assert(len >= min_total_len); 
	
	add_icmp3_headers(sr, packet + icmp3_offset, type, code,
		len - icmp3_offset, packet + ip_offset);
	add_ip_headers(sr, packet + ip_offset, ip_src, ip_dst, len - ip_offset);
	add_ethernet_headers(sr, packet, interface, ether_dhost);
	sr_ethernet_hdr_t *ethernet_packet = (sr_ethernet_hdr_t*)packet;
	assert(ethernet_packet);
	memcpy(ethernet_packet->ether_shost, ether_shost, ETHER_ADDR_LEN);
  sr_send_packet(sr, packet, len, interface);
	return;
}

/*----------------------------------------------------------------------
* Method: sr_prep_and_send_icmp_reply(struct sr_instance *sr, 
* uint8_t *packet, unsigned int len, char *interface, uint32_t ip_src,
* uint32_t ip_dst, uint8_t ether_shost[ETHER_ADDR_LEN], uint8_t 
* ether_dhost[ETHER_ADDR_LEN]);
*
* This method prepares and sends an icmp echo reply back to the sender.
* The packet argument should be a pre-allocated space with enough room
* for ethernet, ip, and ICMP headers.
*
*---------------------------------------------------------------------*/

void sr_prep_and_send_icmp_reply(struct sr_instance *sr, uint8_t *packet, 
unsigned int len, char *interface, uint32_t ip_src, uint32_t ip_dst, 
uint8_t ether_shost[ETHER_ADDR_LEN], uint8_t ether_dhost[ETHER_ADDR_LEN]) {
	
	printf("Arrived in the sr_prep_and_send_icmp_reply\n");
	assert(packet);
	assert(sr);
	assert(interface);
	unsigned int min_total_len = sizeof(sr_ethernet_hdr_t) + sizeof(
		sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
	unsigned int icmp_offset = sizeof(sr_ethernet_hdr_t) + sizeof(
		sr_ip_hdr_t);
	unsigned int ip_offset = sizeof(sr_ethernet_hdr_t);
	assert(len >= min_total_len);
	
	/*Add all three headers*/
	add_icmp_headers(sr, packet + icmp_offset, 0x00, 0x00, 
		len - icmp_offset);
	add_ip_headers(sr, packet + ip_offset, ip_src, ip_dst, len - ip_offset);
	add_ethernet_headers(sr, packet, interface, ether_dhost);
	
	/*Overwrite source host of ethernet packet to ensure correctness*/
	sr_ethernet_hdr_t *ethernet_packet = (sr_ethernet_hdr_t*)packet;
	assert(ethernet_packet);
	memcpy(ethernet_packet->ether_shost, ether_shost, ETHER_ADDR_LEN);
	int status = sr_send_packet(sr, packet, len, interface);
	if (status != 0) {
		fprintf(stderr, "Error when sending icmp reply\n");
		return;
	}
	return;

}

/*---------------------------------------------------------------------
* Method: sr_handle_icmp_request(struct sr_instance *sr, uint8_t *packet,
* unsigned int len, char *interface)
*
* This method is called whenever an ICMP request arrives. It checks if
* the request is an echo request and if so sends an ICMP reply back to
* the sender. Else it ignores the packet.
*
*--------------------------------------------------------------------*/
void sr_handle_icmp_request(struct sr_instance *sr, uint8_t *packet,
unsigned int len, char *interface){

	printf("Reached sr_handle_icmp_request\n");	
	unsigned int icmp_offset = sizeof(sr_ethernet_hdr_t) + sizeof(
		sr_ip_hdr_t);
	sr_icmp_hdr_t *icmp_packet = (sr_icmp_hdr_t*)(packet + icmp_offset);
	assert(icmp_packet);
	sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t*)packet;
	assert(ethernet_header);
	sr_ip_hdr_t *ip_header = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
	assert(ip_header);
	
	/*Check if the checksum is valid*/
	uint16_t calculated_sum = cksum(packet + icmp_offset, len - icmp_offset);
	if (calculated_sum != icmp_packet->icmp_sum){
		printf("Checksum of ICMP invalid");
		return;
	}
	if (icmp_packet->icmp_type == 0x08 && icmp_packet->icmp_code == 0x00) {
		/*Echo request*/
		uint8_t *new_packet = (uint8_t*)malloc(icmp_offset + sizeof(sr_icmp_hdr_t));
		assert(new_packet);
		sr_prep_and_send_icmp_reply(sr, new_packet, len, interface, 
			ip_header->ip_dst,ip_header->ip_src, ethernet_header->ether_dhost, 
			ethernet_header->ether_shost);
		free(new_packet);
	}
	else {
		printf("An unknown ICMP request arrived\n");
		return;
	}	
}

/*---------------------------------------------------------------------
* Method: process_ip_packet(struct sr_instance* sr, uint8_t *packet, 
* unsigned int len, char* interface)
* Scope: Global
*
* This method is called whenever a packet arrives that is determined to
* be an IP packet. The packet buffer should only contain the IP portion,
* the ethernet part should be trimmed off. The packet length, and the 
* name of the receiving interface should also be passed in, along with
* the object representing the router sr_instance. The packet with ethernet
* must also be passed in, as ICMP reply needs it to find the destination
* MAC address.
*
* Note: The packet and name of the receiving interface's memory are 
* handled in sr_vns_comm.c so they are not freed here/
*
*----------------------------------------------------------------------*/

void process_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned
int len, char *interface, uint8_t* packet_with_ethernet){

	printf("Arrived in process_ip_packet function\n");
	assert(sr);
	assert(packet);
	assert(interface);
	assert(len >= sizeof(sr_ip_hdr_t));
	sr_ip_hdr_t *ip_packet = (sr_ip_hdr_t*)(packet);
	assert(ip_packet);
	
	/*Verification of checksum*/
	uint16_t cur_checksum = ip_packet->ip_sum;
	ip_packet->ip_sum = 0; /*Zero out checksum so incoming checksum does not 
	affect the calculation */
	uint16_t calculated_checksum = cksum(packet, sizeof(sr_ip_hdr_t));
	if (calculated_checksum != cur_checksum) {
		fprintf(stderr, "The IP checksum did not match: calculated_checksum is %u\
		and given checksum is %u\n", calculated_checksum, cur_checksum);
		return;
	}
	ip_packet->ip_sum = cur_checksum; /*Put it back to normal in case it needs to 
	be checked later*/

	/* Check if packet is addressed to us */
	struct sr_if *addressed_interface =\
	find_addressed_interface(sr, ip_packet->ip_dst);

	if (addressed_interface != NULL){
		printf("Found a packet addressed to this router\n");
		
		/*Check if icmp request */
		if (ip_packet->ip_p == ip_protocol_icmp) {
			sr_handle_icmp_request(sr, packet_with_ethernet, len + 
			sizeof(sr_ethernet_hdr_t), interface);
		}
		/*Check if TCP or UDP packet*/
		else if (ip_packet->ip_p == 0x0006 || ip_packet->ip_p == 0x0011){
			printf("Found TCP or UDP packet addressed to us\n");
			struct sr_if *outgoing_interface = sr_get_interface(sr, interface);
			if (outgoing_interface == NULL){
				fprintf(stderr, "Outgoing interface null when trying to send resp\
					to TCP/UDP packet\n");
				return;
			}
			uint8_t *new_packet = (uint8_t*)malloc(len+sizeof(sr_ethernet_hdr_t));
			assert(new_packet);

			sr_prep_and_send_icmp3_reply(sr, new_packet,	len + 
				sizeof(sr_ethernet_hdr_t), interface, outgoing_interface->ip,
				ip_packet->ip_src, outgoing_interface->addr,
				((sr_ethernet_hdr_t*)packet_with_ethernet)->ether_shost,
				3, 3);
			return;
		}
		else {
			fprintf(stderr, "There was an unknown packet addressed to us\n");
			return;
		}
	}

	/* If the code reaches here, it is not addressed to this router */
	printf("This packet is not addressed to us, try to forward it\n");
	handle_ip_packet_to_be_sent_out(sr, packet, len, interface,
		packet_with_ethernet);	
}

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*********************** -> Received packet of length %d \n",len);
  printf("REACHED sr_handlepacket\n");
  /*print_hdr_eth(packet);
	print_hdrs(packet, len);*/
  /* fill in code here */
	/*printf("The routing table entries are the following: \n");
	sr_print_routing_table(sr);*/

	int minEthernetLength = sizeof(sr_ethernet_hdr_t);
	if (len < minEthernetLength) {
		fprintf(stderr, "Ethernet header has insufficient length!\n");
		return;
	}
	/*Determine what type of packet we received*/
	uint16_t ethtype = ethertype(packet);

	if (ethtype == ethertype_ip){
		printf("Found IP packet\n");
		int minIPLength = minEthernetLength + sizeof(sr_ip_hdr_t);
		
		if (len < minIPLength) {
			fprintf(stderr, "IP header has insufficient length!\n");
			return;
		}
		else {
			/* Handle IP packet */
			printf("IP packet has sufficient length \n");
			process_ip_packet(sr, packet + sizeof(sr_ethernet_hdr_t), 
				len - sizeof(sr_ethernet_hdr_t), interface, packet);
				return;
		}
	}
	else if (ethtype == ethertype_arp) {
		printf("Found ARP packet \n");
		int minARPLength = minEthernetLength + sizeof(sr_arp_hdr_t);
		
		if (len < minARPLength) {
			fprintf(stderr, "ARP header has insufficient length!\n");
			return;
		}
		else {
			printf("ARP packet has sufficient length \n");
			sr_handle_arp_packet(sr, packet +\
				sizeof(sr_ethernet_hdr_t), len -\
				sizeof(sr_ethernet_hdr_t), interface);
			return;
		}
	}
	else {
		fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
		return;
	}
}/* end sr_ForwardPacket */

