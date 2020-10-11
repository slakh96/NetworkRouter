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
* Method: find_longest_prefix_match(struct sr_rt *routing_table, 
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

struct sr_rt *find_longest_prefix_match(struct sr_rt *routing_table, 
uint32_t ip_dst) {
	printf("Reached find longest prefix match fn, to be implemented");
	/* TODO: Implement this */
	if (routing_table != NULL) {
		uint32_t entry_ip = routing_table->mask.s_addr;
		printf("The entry_ip is %u\n", entry_ip);
	}
	return routing_table;
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
	sr_ethernet_hdr_t *casted_packet = (sr_ethernet_hdr_t *)(packet);
	assert(casted_packet);
	casted_packet->ether_type = ethertype_ip;
	memcpy(casted_packet->ether_dhost, (uint8_t*)mac, 6); /*TODO: Check if this is ok*/
	/* Find the src address from the outgoing interface */
	struct sr_if *outgoing_interface = sr_get_interface(sr, interface);
	if (outgoing_interface == 0) {
		printf("An error occurred; outgoing interface not found");
		/*TODO: Figure out how to handle this*/
		return;
	}
	memcpy(casted_packet->ether_shost, (uint8_t*)outgoing_interface->addr, 6);
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
*packet, unsigned int len, char *interface){
	printf("Reached the handle_ip_packet_to_be_sent_out fn\n");
	assert(sr);
	assert(packet);
	assert(interface);
	sr_ip_hdr_t *ip_packet = (sr_ip_hdr_t*)(packet);
	assert(ip_packet);
	ip_packet->ip_ttl -= 1;
	if (ip_packet->ip_ttl <= 0) {
		fprintf(stderr, "This packet has a TTL of 0; cannot send it\n");
		/* TODO: Handle this error checking */
		return;
	}
	/* Recompute checksum, since the TTL changed */
	uint16_t calculated_checksum = cksum(packet, sizeof(sr_ip_hdr_t));
	ip_packet->ip_sum = calculated_checksum;
	/*TODO: make sure checksum is updated in packet as well as ip_packet*/
	struct sr_rt *best_match = find_longest_prefix_match(sr->routing_table,
	ip_packet->ip_dst);
	if (best_match == NULL) {
		/*TODO: Send error message if no best match found*/
		printf("No best match found\n");
		return;
	}
	/* Check ARP cache for MAC address corresponding to the next-hop IP*/
	struct sr_arpentry *arp_cache_entry = sr_arpcache_lookup(&(sr->cache), 
	ip_packet->ip_dst);
	if (arp_cache_entry == NULL) { /* No MAC addr found; make ARP req */
		uint8_t *packet_with_ethernet = \
		(uint8_t*)malloc(len + sizeof(sr_ethernet_hdr_t));
		unsigned char broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
		add_ethernet_headers(sr, packet_with_ethernet, interface,
		broadcast_mac);
		/*Add the IP part to the end of the packet*/
		memcpy(packet_with_ethernet + sizeof(sr_ethernet_hdr_t), packet, len);
		/*Add this request to the arpcache queued requests*/
		struct sr_arpreq *arp_req = sr_arpcache_queuereq(&(sr->cache),
		ip_packet->ip_dst, packet_with_ethernet, len + sizeof(sr_ethernet_hdr_t),
		interface);
		if (arp_req == NULL){
			printf("Error occurred; the arp_req returned from starter code was\
			NULL....");
			/*TODO Figure out if we need to handle this case */
			return;
		}
		/*Send out request for the MAC address*/
		sr_handle_arpreq(sr, arp_req);
	}
	else { /*MAC addr found; create and send IP request*/
		printf("Found MAC; sending IP request\n");
		uint8_t *new_packet = prepare_to_send_ip_req(sr, packet, len, 
		interface, arp_cache_entry);
		free(arp_cache_entry);
		struct sr_if *outgoing_interface = sr_get_interface(sr, interface);
		if (outgoing_interface == 0) {
			printf("An error occurred; outgoing interface not found");
			/*TODO: Figure out how to handle this*/
			return;
		}
		int status = sr_send_packet(sr, new_packet, len + 
		sizeof(sr_ethernet_hdr_t), interface);
		if (status != 0){
			printf("An error occurred when sending packet!\n");
		}
		/*free(outgoing_interface); TODO see if we have to do this */
		free(new_packet);
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
* the object representing the router sr_instance.
*
* Note: The packet and name of the receiving interface's memory are 
* handled in sr_vns_comm.c so they are not freed here/
*
*----------------------------------------------------------------------*/

void process_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned
int len, char *interface){

	printf("Arrived in process_ip_packet function");
	assert(sr);
	assert(packet);
	assert(interface);
	assert(len >= sizeof(sr_ip_hdr_t));
	sr_ip_hdr_t *ip_packet = (sr_ip_hdr_t*)(packet);
	assert(ip_packet);
	uint16_t calculated_checksum = cksum(packet, sizeof(sr_ip_hdr_t));
	if (calculated_checksum != ip_packet->ip_sum) { /* Verify checksum */
		fprintf(stderr, "The IP checksum did not match: calculated_checksum is %u\
		and given checksum is %u\n", calculated_checksum, ip_packet->ip_sum);
		return;
	}
	/* Check if packet is addressed to us */
	struct sr_if *addressed_interface =\
	find_addressed_interface(sr, ip_packet->ip_dst);
	if (addressed_interface != NULL){
		printf("Found a packet addressed to this router\n");
		/* TODO: Handle packets addressed to this router */
	}

	/* If the code reaches here, it is not addressed to this router */
	printf("This packet is not addressed to us, try to forward it\n");
	handle_ip_packet_to_be_sent_out(sr, packet, len, interface);	
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

  printf("*** -> Received packet of length %d \n",len);
  printf("REACHED sr_handlepacket\n");
  print_hdr_eth(packet);
	print_hdrs(packet, len);
  /* fill in code here */
	printf("The routing table entries are the following: \n");
	sr_print_routing_table(sr);
	int minEthernetLength = sizeof(sr_ethernet_hdr_t);
	if (len < minEthernetLength) {
		fprintf(stderr, "Ethernet header has insufficient length!\n");
	}
	uint16_t ethtype = ethertype(packet);
	if (ethtype == ethertype_ip){
		printf("Found IP packet\n");
		int minIPLength = minEthernetLength + sizeof(sr_ip_hdr_t);
		if (len < minIPLength) {
			fprintf(stderr, "IP header has insufficient length!\n");
		}
		else {
			/*TODO: Handle IP packet here*/
			printf("IP packet has sufficient length \n");
			process_ip_packet(sr, packet + sizeof(sr_ethernet_hdr_t), len - sizeof(sr_ethernet_hdr_t), interface);
		}
	}
	else if (ethtype == ethertype_arp) {
		printf("Found ARP packet \n");
		int minARPLength = minEthernetLength + sizeof(sr_arp_hdr_t);
		if (len < minARPLength) {
			fprintf(stderr, "ARP header has insufficient length!\n");
		}
		else {
			printf("ARP packet has sufficient length \n");
			sr_handle_arp_packet(sr, packet +sizeof(sr_arp_hdr_t), 
			len - sizeof(sr_ethernet_hdr_t), interface);
		}
	}
	else {
		fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
	}
}/* end sr_ForwardPacket */

