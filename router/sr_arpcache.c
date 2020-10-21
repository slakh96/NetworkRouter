#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include <assert.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_utils.h"

/*
	This function creates and returns a sr_arp_hdr given some information
	passed as parameters including opcode, sender ip address, receiving ip
	address, sending MAC address, receiving MAC address.
*/
struct sr_arp_hdr create_arp_hdr(unsigned short ar_op, uint32_t ar_sip,
uint32_t ar_tip, unsigned char ar_sha[6], unsigned char ar_tha[6]){
	
	printf("Reached create_arp_hdr fn\n");
	struct sr_arp_hdr arp_hdr;
	arp_hdr.ar_op = htons(ar_op);
	arp_hdr.ar_sip = ar_sip;
	arp_hdr.ar_tip = ar_tip;
	memcpy(arp_hdr.ar_sha, ar_sha, 6);
	memcpy(arp_hdr.ar_tha, ar_tha, 6);
	arp_hdr.ar_hrd = htons(0x0001);
	arp_hdr.ar_pro = htons(0x0800);
	arp_hdr.ar_hln = 6;
	arp_hdr.ar_pln = 4;
	return arp_hdr;
}


/*
	This function gets called whenever we need to prepare and send an ARP
	request; it adds ethernet headers, the destination broadcast MAC address,
	and calls the appropriate function to send out the ARP request. Takes in
	the ARP request pointer, and router instance pointer.
*/
void sr_prep_and_send_arpreq(struct sr_instance *sr, char *interface,
unsigned short ar_op, uint32_t ar_sip,
uint32_t ar_tip, unsigned char ar_sha[6], unsigned char ar_tha[6],
unsigned short outgoing_opcode){

	printf("Reached sr_prep_and_send_arpreq\n");
	assert(sr);
	assert(interface);
	unsigned int eth_pkt_size = sizeof(struct sr_arp_hdr) +\
		sizeof(sr_ethernet_hdr_t);
	uint8_t *packet_with_ethernet =\
		(uint8_t*)calloc(1, eth_pkt_size);
	assert(packet_with_ethernet);
	
	add_ethernet_headers(sr, packet_with_ethernet, interface, ar_tha);
	sr_ethernet_hdr_t* eth_pkt = (sr_ethernet_hdr_t*)packet_with_ethernet;
	eth_pkt->ether_type = htons(ethertype_arp);

	struct sr_arp_hdr created_arp_hdr = create_arp_hdr(outgoing_opcode,
		ar_sip, ar_tip, ar_sha, ar_tha);
	/*Add the arp part to the request which already has ethernet headers*/
	memcpy(packet_with_ethernet + sizeof(sr_ethernet_hdr_t), &created_arp_hdr, 
		sizeof(struct sr_arp_hdr));
	/*printf("Printing all headers of the packet to send out:\n");
	print_hdrs(packet_with_ethernet, eth_pkt_size);*/
	int status = sr_send_packet(sr, packet_with_ethernet, eth_pkt_size,
		interface);
	printf("Sent ARP packet\n");
	if (status != 0){
		fprintf(stderr, "Error when sending ARP req\n");
		free(packet_with_ethernet);
		return;
	}
	free(packet_with_ethernet);
}

/*
	This function gets called whenever we want to handle CACHED ARP requests. 
	It checks	if the request hasn't been sent out in the past second; 
	if so sends the req	out if it has been sent less than 5 times. If the 
	request has been sent out	at least 5 times, it sends back an ICMP 
	host unreachable to address of each	packet waiting on this request, then 
	destroys the ARP request. Takes in the ARP request pointer, and router ptr.
*/
void sr_handle_arpreq(struct sr_instance *sr, struct sr_arpreq *arp_req) {
	
	assert(sr);
	assert(arp_req);
	time_t cur_time = time(NULL); /*Gives the time since Jan 1 1970 in seconds*/

	if (cur_time - arp_req->sent >= 1){ /*If haven't sent in past second*/
		assert(arp_req->packets);/*TODO: Ensure that this is a correct assertion to make*/
		       
		unsigned char broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
		struct sr_if *outgoing_interface = sr_get_interface(sr, arp_req->packets->iface);
		if (outgoing_interface == 0) {
			fprintf(stderr, "An error occurred; outgoing interface not found\n");
			return;
		}

		if (arp_req->times_sent >= 5){
			struct sr_packet *cur_packet = arp_req->packets;
			while (cur_packet != NULL){
				sr_ethernet_hdr_t *ethernet_packet = (sr_ethernet_hdr_t*)cur_packet->buf;
				assert(ethernet_packet);
				sr_ip_hdr_t *ip_header = (sr_ip_hdr_t*)(cur_packet->buf +\
					sizeof(sr_ethernet_hdr_t));
				assert(ip_header);

				int total_size = sizeof(sr_ethernet_hdr_t) + ip_header->ip_len +
					sizeof(sr_icmp_t3_hdr_t);
				uint8_t *new_packet = (uint8_t*)calloc(1, total_size);
				assert(new_packet);
				
				struct sr_if *outgoing_interface = sr_get_interface(sr, cur_packet->iface);
				if (outgoing_interface == NULL){
					fprintf(stderr, "Error getting outgoing interface when sending ARP req\n");
					return;
				}

				sr_prep_and_send_icmp3_reply(sr, cur_packet->buf, total_size, cur_packet->iface,
					outgoing_interface->ip, ip_header->ip_dst, outgoing_interface->addr, 
					ethernet_packet->ether_shost, 3, 1);
				cur_packet = cur_packet->next;
			}
			sr_arpreq_destroy(&(sr->cache), arp_req);
			return;
		}
		else {
			/*The sender ip comes from the interface of the first packet*/
			uint32_t sender_ip = outgoing_interface->ip;
			uint32_t receiving_ip = arp_req->ip;

			sr_prep_and_send_arpreq(sr, arp_req->packets->iface,
				arp_hrd_ethernet, sender_ip, receiving_ip, outgoing_interface->addr, 
				broadcast_mac, arp_op_request);
			arp_req->sent = time(NULL); /*Recompute cur time, to be more accurate*/
			arp_req->times_sent++;
		}
	}
}

/*
	This function gets called when we want to determine if a packet is addressed
	to us. It takes a router instance, and the ip of the incoming packet and
	returns a pointer to the applicable interface if it is addressed to us or
	null otherwise.
*/

struct sr_if *find_addressed_interface(struct sr_instance *sr, uint32_t ip){
	struct sr_if *cur_interface = sr->if_list; /* Start at first iface of lst*/ 
	while (cur_interface != NULL) {
		if (cur_interface->ip == ip) {
			return cur_interface;
		}
		cur_interface = cur_interface->next;
	}
	return NULL;
}

/*
	This function handles an incoming ARP reply; adds the mapping to the cache, 
	and sends out each packet which was waiting for this IP->MAC mapping.
*/

void sr_handle_arp_reply(struct sr_instance *sr, sr_arp_hdr_t* arp_header,
unsigned int len, char *interface){

	printf("Reached sr_handle_arp_reply function\n");
	assert(sr);
	assert(arp_header);
	assert(interface);
	
	/*Insert new mapping into the cache*/
	struct sr_arpreq *arpreq = sr_arpcache_insert(&(sr->cache), 
	arp_header->ar_sha, arp_header->ar_sip);
	if (arpreq == NULL){
		printf("No one is waiting on this packet\n");
		return; /*No packets were waiting on this mapping*/
	}

	/*Go through each waiting packet and send it*/
	struct sr_packet *cur_packet = arpreq->packets;
	while (cur_packet != NULL){
		sr_ethernet_hdr_t *ethernet_buf = (sr_ethernet_hdr_t*)cur_packet->buf;
		assert(ethernet_buf);
		sr_ip_hdr_t *ip_packet = (sr_ip_hdr_t*)(cur_packet->buf + 
			sizeof(sr_ethernet_hdr_t));
		assert(ip_packet);

		/*Set the newly discovered destination MAC address*/
		memcpy(ethernet_buf->ether_dhost, arp_header->ar_sha, ETHER_ADDR_LEN);
		sr_icmp_hdr_t *icmp_packet = (sr_icmp_hdr_t*)(cur_packet->buf + 
			sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
		assert(icmp_packet);
		icmp_packet->icmp_sum = 0;
		icmp_packet->icmp_sum = cksum(cur_packet->buf + 
			sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), ntohs(ip_packet->ip_len)
			- sizeof(sr_ip_hdr_t));
		printf("Preparing to send out the following queued IP packet\n");
		print_hdrs(cur_packet->buf, cur_packet->len);
		printf("printed=====================================================\n");
		int status = sr_send_packet(sr, cur_packet->buf, cur_packet->len,
			cur_packet->iface);
		if (status != 0){
			fprintf(stderr, "Error when sending a queued packet\n");
		}
		struct sr_packet *next_packet = cur_packet->next;
		cur_packet = next_packet;
	}
	/*Delete the ARP request once all of the packets have been sent */
	printf("Sent all of the packets, deleting the ARP request\n");
	sr_arpreq_destroy(&(sr->cache), arpreq);

}

/*
	This function gets called when we want to handle an incoming ARP packet.
	If this is an ARP request to us, a reply is constructed using a helper and
	sent back to the requester. If it is an ARP reply addressed to us, we cache
	it, then go through the request queue and send all outstanding packets
	which were waiting on this mapping of IP->MAC. 

	This function takes in the router instance, the packet containing ONLY the
	sr_arp_hdr, the length of the packet, and the receiving interface name.
*/

void sr_handle_arp_packet(struct sr_instance *sr, uint8_t *packet, unsigned
int len, char *interface){
	
	printf("Reached the sr_handle_arp_packet function\n");
	assert(sr);
	assert(packet);
	assert(interface);
	assert(len >= sizeof(sr_arp_hdr_t));
	sr_arp_hdr_t *arp_header = (sr_arp_hdr_t*)packet;
	assert(arp_header);
	/*print_hdr_arp(packet);*/
	/*Determine if ARP packet is addressed to us */
	struct sr_if *addressed_interface =\
		find_addressed_interface(sr, arp_header->ar_tip);
	if (addressed_interface == NULL){
		printf("This ARP packet is not addressed to us; ignore\n");
		return;
	}
	if (ntohs(arp_header->ar_op) == arp_op_request){
		/*The sender needs a MAC addr from us*/

		/*Reverse the send and receiving addresses to send back*/
		uint32_t dst_ip = arp_header->ar_sip;
		uint32_t src_ip = addressed_interface->ip;
		
		sr_prep_and_send_arpreq(sr, interface, arp_hrd_ethernet, src_ip, 
			dst_ip, addressed_interface->addr, arp_header->ar_sha, arp_op_reply);
	
	}
	else if (ntohs(arp_header->ar_op) == arp_op_reply) {
		/*The sender is replying to our arp request*/
		sr_handle_arp_reply(sr, arp_header, len, interface);
	}
	else {
		/*Some weird packet; don't reply*/
		printf("Unknown ARP packet type\n");
		return;
	}

}


/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
    assert(sr);

	  struct sr_arpreq *cur_req = sr->cache.requests;
		struct sr_arpreq *next_req = NULL;
		while (cur_req != NULL){
			next_req = cur_req->next;
			sr_handle_arpreq(sr, cur_req);
			cur_req = next_req;
		}
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

