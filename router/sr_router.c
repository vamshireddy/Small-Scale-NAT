/**********************************************************************

 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu, k.vamshi2008@gmail.com
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
#include <limits.h>
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#define IP_PROTOCOL 0x0800
#define ARP_PROTOCOL 0x0806
#define TCP_PROTOCOL 0x06
#define ICMP_PROTOCOL 0x01
#define UDP_PROTOCOL 0x11

/* ----------------------------------- THINGS TO HANDLE ------------------------------------
1) ARP Caching and queing the packets ( Done ) 
2) ARP Cache Eviction ( Done )
3) ICMP MESSAGES ( EcHO DONE )
4) IP FOREWARDING ( Done )
5) ARP REPLY ( Done )
6) ARP REQUEST ( Done )
7) TCP, UDP Forewarding (Done )
8) Destination Host Unreachable when the next hop is not responding to ARP requests for more than 5 times ( NOT DONE )
------------------------------------------------------------------------------------------*/

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

uint8_t* make_ICMP(struct sr_instance* sr,uint8_t* packet,int len,uint8_t type,uint8_t code);

uint8_t* make_IP_packet(uint8_t ver_hlen,uint8_t tos,uint16_t len,uint16_t id,uint16_t off,uint8_t ttl,uint8_t prot, \
			uint32_t src,uint32_t dst);
void handle_ICMP(struct sr_instance* sr,uint8_t* ip_packet_start,int len,short type,short code,char* interface,int);

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
    sr_arpcache_dump(&sr->cache);
} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 )* interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

/* This function will check the given destination IP with all the interfaces
To check wheather it is destined to router or not*/


int check_match_all_interfaces(struct sr_if* interface_list,uint32_t pack_ip)
{
	while( interface_list!= NULL )
	{
		if( interface_list->ip == pack_ip )
		{
			return 1;
		}
		interface_list = interface_list->next;
	}
	return 0;
}

int check_checksum(uint8_t* packet,int size)
{	
	if(cksum(packet,size) == 0xffff )
		return 1;
	else
		return 0;
}

void ARP_request_send(struct sr_instance* sr,uint32_t gateway_IP,struct sr_if* interface)
{
	/* Build both ethernet and ARP header for the request packet */
	uint8_t* packet = (uint8_t*)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
	
	/* Build ethernet header */
	sr_ethernet_hdr_t* new_eth = (sr_ethernet_hdr_t*)packet;
	
	memcpy(new_eth->ether_shost,interface->addr,sizeof(uint8_t)*6);
	memset(new_eth->ether_dhost,255,sizeof(uint8_t)*6);
	new_eth->ether_type = htons(ARP_PROTOCOL);

	/* Build ARP header */
	sr_arp_hdr_t* arp_reply_structure = (sr_arp_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t));
	
	arp_reply_structure->ar_op = htons(0x0001);
	memcpy(arp_reply_structure->ar_sha,interface->addr,sizeof(uint8_t)*6);
	bzero(arp_reply_structure->ar_tha,sizeof(uint8_t)*6);
	arp_reply_structure->ar_sip = interface->ip;
	arp_reply_structure->ar_tip = gateway_IP;
	arp_reply_structure->ar_pro = htons(0x0800);
	arp_reply_structure->ar_pln = 0x04;
	arp_reply_structure->ar_hrd = htons(0x0001);
	arp_reply_structure->ar_hln = 0x06;
	
	/* Now everything is complete */
	/* Now send the packet */
	sr_send_packet(sr,packet,sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t),interface->name);
}


void handle_ARP_req(struct sr_instance* sr, struct sr_arpcache* cache, struct sr_arpreq* req_queue)
{
	/* Get the current time */
	time_t time_now = time(NULL);
	if ( difftime(time_now,req_queue->sent) > 1.0 )
	{
		/* If the last request sent time is more than 1 second then send again */
		if( req_queue->times_sent >= 5)
		{
			/* ICMP error, destination host unreachable to all the packets on this queue */
			struct sr_packet* packets = req_queue->packets;
			while( packets ) 
			{
				uint8_t* ip_packet = packets->buf+sizeof(sr_ethernet_hdr_t);
				handle_ICMP(sr,ip_packet,packets->len-sizeof(sr_ethernet_hdr_t),3,1,packets->iface,0);
				packets = packets->next;
			}
			sr_arpreq_destroy(cache,req_queue);
		}
		else
		{
			/* Send ARP request */
			/* Check if there are any packets */
			if( req_queue->packets != NULL )
			{
				/* Get the interface */
				struct sr_if* interf = sr_get_interface(sr,req_queue->packets->iface);
				uint32_t gateway_IP = req_queue->ip;
				ARP_request_send(sr,gateway_IP,interf);
				req_queue->times_sent++;
				req_queue->sent = time_now;
			}
		}
	}

}

struct sr_rt* LPM(struct sr_rt* table, uint32_t ip)
{
	struct sr_rt* target = NULL;
	/* Mask value stores the prefix value to maintain the max one */
	uint32_t mask_value = 0;
	while( table!=NULL )
	{
		/* Get the subnet id */
		uint32_t sub_net_ip = ((table->mask).s_addr) & (ip);
		/* Compute the mask value to comapare for max length prefix */
		uint32_t val = ((table->mask).s_addr) & 0xFFFFFFFF;
		
		/* If sub_net_ip is zero, it means it is default route and its should be accepted */
		if( ( sub_net_ip == (table->dest).s_addr ) || ( sub_net_ip == 0 ) ) 
		{
			if( val >= mask_value )
			{
				mask_value = val;
				target = table;
			}
		}
		table = table->next;
	}
	return target;
}

/* This will foreward the given IP packet 
It checks for the Destination IP address and finds appropriate interface (LPM) and sends out! */
int forward_packet(struct sr_instance* sr,uint8_t* packet,int len,int packet_src_iface)
{
	uint32_t ip;
	sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)packet;
	/* Get Dest IP */
	ip = ip_header->ip_dst;

	/* This target variable stores the next hop */
	struct sr_rt* target = NULL;
	/* Perform LPM and get the target routing table entry which has the interface to pass and next hop IP */
	target = LPM(sr->routing_table,ip);
	/* Now the next hop ip (dest->gw)  is known and the interface also */
	if( target == NULL )
	{
		/* ICMP Destination Unreachable */
		/* There is no routing table entry for this destination IP address
		Now we have to send this packet encapsulated in ICMP packet with 3,0( Destiantion Network Unreachable )
		with src address of the incoming interface address and destination address as the source */
		
		/* We have IP packet, Now encapsulate in the ICMP */
		sr_icmp_hdr_t* ih = (sr_icmp_hdr_t*)(packet+sizeof(sr_ip_hdr_t));
		if( (ip_header->ip_p == ICMP_PROTOCOL) && (ih->icmp_type != 8) )
		{
			/* Dont send an ICMP for ICMP */
			return;
		}
		print_hdr_ip(packet);
		int size = sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_hdr_t)+sizeof(sr_ip_hdr_t)+8;

		uint8_t* complete_packet = (uint8_t*) malloc(sizeof(uint8_t)*size);

		uint8_t* icmp_start = make_ICMP(sr,packet,len,3,0);
		
		
		struct sr_if* src_if = sr_get_interface(sr,packet_src_iface);
		

		uint8_t* ip_start = make_IP_packet(*((uint8_t*)ip_header),(0x0000), htons(size), 0x0000, 0x0000,64,0x01, \
								src_if->ip,ip_header->ip_src);
		
		/* Foreward the ICMP packet with 3,0 to the src host */
		/* If the entry is again wrong, then dont send the ICMP for ICMP */
		
		memcpy(complete_packet,ip_start,sizeof(sr_ip_hdr_t));
		memcpy(complete_packet+sizeof(sr_ip_hdr_t),icmp_start,sizeof(sr_icmp_hdr_t)+sizeof(sr_ip_hdr_t)+8);
		
		forward_packet(sr,complete_packet,size,packet_src_iface);
		return;
	}

	/* Now query for the Ethernet details */
	/* Get the router interface from where the packet should leave */
	struct sr_if* src_interface = sr_get_interface(sr,target->interface);
	/* Get the ARP entry for the next hop IP */
	struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache,(target->gw.s_addr));
	/* Now build the ethernet header */	
	
	uint8_t* complete_packet = (uint8_t*)malloc(sizeof(sr_ethernet_hdr_t)+len);

	memcpy(complete_packet+sizeof(sr_ethernet_hdr_t),packet,len);	
	
	/* Fill in all the details of the ethernet */

	sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)complete_packet;
	memcpy(eth_hdr->ether_shost,src_interface->addr,sizeof(uint8_t)*6);
	eth_hdr->ether_type = htons(IP_PROTOCOL);

	/* If entry is NULL, It means that there is no cache entry in ARP Table */
	/* If not NULL, Then use the entry for next hop MAC address */

	/*assert(entry!=NULL);*/
	
	if( entry == NULL )
	{
		/* Destination MAC is not known ! */
		memset(eth_hdr->ether_dhost,0,sizeof(uint8_t)*6);
		/* Cache doesnt have this entry, So request it */
		struct sr_arpreq* req = sr_arpcache_queuereq(&sr->cache,target->gw.s_addr,complete_packet,len+sizeof(sr_ethernet_hdr_t) \
								,target->interface);
		assert(req!=NULL);
		/* Free the packet, as we dont need it. It has been copied to other buffer in the request queue */
		handle_ARP_req(sr, &sr->cache,req);
	}
	else
	{
		/* Destination MAC is known, So use it! */	
		memcpy(eth_hdr->ether_dhost,entry->mac,sizeof(uint8_t)*6);
		/* Now send the packet to the target interface */
		sr_send_packet(sr,complete_packet,sizeof(sr_ethernet_hdr_t)+len,target->interface);
		free(entry);
	}
}


uint8_t* make_ICMP_packet_echo(uint8_t* icmp_packet,int len)
{
	/* Returns ICMP packet with the payload and now the length will be len + sizeof(icmp_hdr)
	*/
	uint8_t* new_packet = (uint8_t*)malloc(len);
	memcpy(new_packet,icmp_packet,len);
	sr_icmp_hdr_t* header = (sr_icmp_hdr_t*)new_packet;
	header->icmp_type = 0;
	header->icmp_code = 0;
	header->icmp_sum = 0;
	header->icmp_sum = cksum(new_packet,len);
	return new_packet;
}

uint8_t* make_IP_packet(uint8_t ver_hlen,uint8_t tos,uint16_t len,uint16_t id,uint16_t off,uint8_t ttl,uint8_t prot, \
			uint32_t src,uint32_t dst)
{
	sr_ip_hdr_t* packet = (sr_ip_hdr_t*)malloc(sizeof(sr_ip_hdr_t));
	*((uint8_t*)packet) = ver_hlen;
	packet->ip_tos = tos;
	packet->ip_len = len;
	packet->ip_id = id;
	packet->ip_off = off;
	packet->ip_ttl = ttl;
	packet->ip_sum = 0;
	packet->ip_p = prot;
	packet->ip_src = src;
	packet->ip_dst = dst;
	packet->ip_sum = cksum((uint8_t*)packet,sizeof(sr_ip_hdr_t));
	return (uint8_t*)packet;
}

uint8_t* make_ICMP(struct sr_instance* sr,uint8_t* packet,int len,uint8_t type,uint8_t code)
{
	/* Handle ICMP packets */
	/* TTL expired type=11 code = 0 */
	/* Now make a new packet with IP header and ICMP header and IP(20 B) TCP(8 B) */
	uint8_t* icmp_p = (uint8_t*)malloc(sizeof(sr_icmp_hdr_t)+sizeof(sr_ip_hdr_t)+8);
	sr_icmp_hdr_t* icmp_h = (sr_icmp_hdr_t*)icmp_p;
	icmp_h->icmp_type = type;
	icmp_h->icmp_code = code;
	icmp_h->icmp_sum = 0;
	icmp_h->unused = 0;	
	uint8_t* payload_icmp = icmp_p + sizeof(sr_icmp_hdr_t);
	/* Copy the ip header and 1st 8bytes of tcp header */
	memcpy(payload_icmp,packet,sizeof(sr_ip_hdr_t)+8);
	/* Now calculate the Checksum */
	icmp_h->icmp_sum = cksum(icmp_p,sizeof(sr_icmp_hdr_t)+sizeof(sr_ip_hdr_t)+8);
	return icmp_p;
}

void handle_ICMP(struct sr_instance* sr,uint8_t* ip_packet_start,int len,short type,short code,char* interface,int to_router)
{

		
		sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)ip_packet_start;
		/* No TCP/UDP stack running in the router */
		/* Send ICMP Packet saying port unreachable */
		/* Type = 3 and code = */
		int size = sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_hdr_t)+sizeof(sr_ip_hdr_t)+8;

		uint8_t* complete_packet = (uint8_t*)malloc(size);
		uint8_t* icmp_pack = make_ICMP(sr,ip_packet_start,len,type,code);
		
		/* Get the interface to know the interface from where the ICMP TTL expored message should be sent */
		struct sr_if* src_interface = sr_get_interface(sr,interface);
		
		uint32_t src_IP;
		if(type == 11)
		{
			src_IP = src_interface->ip;
		}
		else if(type == 3 && to_router == 1)
		{
			src_IP = ip_header->ip_dst;
		}
		else if(type == 3 && to_router == 0)
		{
			src_IP = src_interface->ip;
		}
		
		uint8_t* ip_pack = make_IP_packet(*((uint8_t*)ip_header),(0x0000), htons(size), 0x0000, 0x0000,64,0x01, \
									/*ip_header->ip_dst*/src_IP,ip_header->ip_src);
		memcpy(complete_packet,ip_pack,sizeof(sr_ip_hdr_t));
		memcpy(complete_packet+sizeof(sr_ip_hdr_t),icmp_pack,sizeof(sr_icmp_hdr_t)+sizeof(sr_ip_hdr_t)+8);
		forward_packet(sr,complete_packet,size,interface);
}

int router_handle_packet(struct sr_instance* sr,uint8_t* ip_packet_start,int len,char* interface)
{
	sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)ip_packet_start;
	/* Check if the above protocol is TCP/UDP or ICMP */
	
	uint8_t protocol = ip_header->ip_p;
	if( protocol == TCP_PROTOCOL || protocol == UDP_PROTOCOL)
	{
		handle_ICMP(sr,ip_packet_start,len,3,3,interface,1);
	}
	else if( protocol == ICMP_PROTOCOL )
	{
		/* Its an ICMP packet */
		/* check if it is ICMP echo request or not */
		uint16_t data_len = 0;
		uint8_t* data = 0;
		uint8_t* icmp_start = make_ICMP_packet_echo(ip_packet_start+sizeof(sr_ip_hdr_t),len-sizeof(sr_ip_hdr_t));
		uint8_t* ip_start = make_IP_packet( *((uint8_t*)ip_header), ip_header->ip_tos, htons(len), \
				ip_header->ip_id,ip_header->ip_off, 64, ip_header->ip_p,
				ip_header->ip_dst, ip_header->ip_src);
		uint8_t* final_packet = (uint8_t*)malloc(len);
		memcpy(final_packet,ip_start,sizeof(sr_ip_hdr_t));
		memcpy(final_packet + sizeof(sr_ip_hdr_t),icmp_start,len-sizeof(sr_ip_hdr_t));
		free(ip_start);
		free(icmp_start);	
		/*
		print_hdr_icmp(final_packet+sizeof(sr_ip_hdr_t));
		*/
		forward_packet(sr,final_packet,len,interface);
	}
	else
	{
		assert(0);
	}
}


int decrement_TTL(sr_ip_hdr_t* ip_hdr)
{
	/* Decrement and check for 0 */
	ip_hdr->ip_ttl -= 1;
	if( ip_hdr->ip_ttl == 0 )
	{
		return 0;
	}
	return 1;
}

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

	sr_ethernet_hdr_t* eth_header = (sr_ethernet_hdr_t*)packet;
	/* printf("The type is %x\n",ntohs(eth_header->ether_type));*/

	if( ntohs(eth_header->ether_type) == IP_PROTOCOL)
	{
		/* Its an IP Packet */
		printf("Its an IP Packet\n");
		/* Check the checksum of the packet */
		uint8_t* ip_packet = packet + sizeof(sr_ethernet_hdr_t);
		if(check_checksum(ip_packet,sizeof(sr_ip_hdr_t)) == 0)
		{
			/* Handle ICMP Error message */
			return;
		}
		else
		{
			/* Checksum is fine, Now do the functions */
			sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)ip_packet;
			/*print_hdr_ip(ip_packet);*/
			if( decrement_TTL(ip_header) == 0 )
			{
				/* Send ICMP packet for Time Limit Exceeded*/
				
				ip_header->ip_sum = 0;
				ip_header->ip_ttl = 1;
				ip_header->ip_sum = cksum(ip_packet,sizeof(sr_ip_hdr_t));
				/*make_ICMP_packet();
				make_IP_packet();*/
				/* Check wheather the Destination is this router  */
				if( check_match_all_interfaces ( sr->if_list, ip_header->ip_dst) == 1 )
				{
					printf("I am here in TTL 0 \n\n\\n");
					uint8_t protocol = ip_header->ip_p;
					if( protocol == TCP_PROTOCOL || protocol == UDP_PROTOCOL)
					{
						/* This is having UDP or TCP as payload */
						/* So, just include this packet as payload and send the ICMP packet */
						handle_ICMP(sr,ip_packet,len-sizeof(sr_ethernet_hdr_t),3,3,interface,1);
					}
					else
					{
						/* Its ICMP protocol */
						/* Check if it is echo request , If it is then send echo reply */
						sr_icmp_hdr_t* icmp = (sr_icmp_hdr_t*)(ip_packet+sizeof(sr_ip_hdr_t));
						if( icmp->icmp_type == 8 && icmp->icmp_code == 0)
						{
							
							int length = len - sizeof(sr_ethernet_hdr_t);
							uint8_t* data = 0;
			uint8_t* icmp_start = make_ICMP_packet_echo(ip_packet+sizeof(sr_ip_hdr_t),length-sizeof(sr_ip_hdr_t));
			uint8_t* ip_start = make_IP_packet( *((uint8_t*)ip_header), ip_header->ip_tos, htons(length), \
							ip_header->ip_id,ip_header->ip_off, 64, ip_header->ip_p,\
							ip_header->ip_dst, ip_header->ip_src);
							uint8_t* final_packet = (uint8_t*)malloc(len);
							memcpy(final_packet,ip_start,sizeof(sr_ip_hdr_t));
						memcpy(final_packet + sizeof(sr_ip_hdr_t),icmp_start,\
								length-sizeof(sr_ip_hdr_t));
						free(ip_start);
						free(icmp_start);	
						forward_packet(sr,final_packet,length,interface);
						}
						else
							handle_ICMP(sr,ip_packet,len-sizeof(sr_ethernet_hdr_t),11,0,interface,1);
					}
				}
				else
				{
					handle_ICMP(sr,ip_packet,len-sizeof(sr_ethernet_hdr_t),11,0,interface,0);
				}
				return;
			}
			/* Calculate new checksum after TTL updation */
			ip_header->ip_sum = 0;
			ip_header->ip_sum = cksum(ip_packet,sizeof(sr_ip_hdr_t));

			/*print_hdr_ip(ip_packet);*/
			/* Check if the packet is destined to any of its interfaces */
			/* Dont free this */
			if( check_match_all_interfaces ( sr->if_list, ip_header->ip_dst) == 1 )
			{
				/* Now its destined to router, so router should handle it 
				It Should check for the Transport layer protocol and should appropriately send ICMP packets*/
				router_handle_packet(sr,ip_packet,len-sizeof(sr_ethernet_hdr_t),interface);
			}
			else
			{
				/* Packet should be forewarded */
				forward_packet(sr,ip_packet,len,interface);
			}
		}
	}
	else
	{
		printf("Its an ARP Packet\n");
		/* Its an ARP Packet */

		uint8_t* arp_packet = packet + sizeof(sr_ethernet_hdr_t);
		/* Construct ARP structure */
		sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*)arp_packet;
		
		/* Check if the packet is request to the router */
		int dst_ip = ntohl(arp_header->ar_tip);
		
		struct sr_if* arp_interface = sr_get_interface(sr,interface);
		int interface_ip = ntohl(arp_interface->ip);

		if( dst_ip == interface_ip )
		{
			/* It is destined correctly */

			uint8_t op_code = ntohs(arp_header->ar_op);
		
			if( op_code == 1 )
			{
				/* ARP Request */
				uint8_t* arp_reply_packet;
				arp_reply_packet = (uint8_t*)malloc(sizeof(sr_ethernet_hdr_t)+1500);
				bzero(arp_reply_packet,sizeof(sr_ethernet_hdr_t)+1500);
				/* Create both ethernet and ARP structures */
				sr_ethernet_hdr_t* new_eth = (sr_ethernet_hdr_t*)arp_reply_packet;
				/* Fill in all the details of ethernet frame */
				memcpy(new_eth->ether_dhost,eth_header->ether_shost,sizeof(uint8_t)*6);
				memcpy(new_eth->ether_shost,arp_interface->addr,sizeof(uint8_t)*6);
				new_eth->ether_type = htons(ARP_PROTOCOL);

				/* Fill in all the details of ARP */
				uint8_t* arp_reply_segment  = arp_reply_packet+ sizeof(sr_ethernet_hdr_t);
				memcpy(arp_reply_segment,arp_packet,sizeof(sr_arp_hdr_t));
				sr_arp_hdr_t* arp_reply_structure = (sr_arp_hdr_t*)arp_reply_segment;
				arp_reply_structure->ar_op = htons(2);
				memcpy(arp_reply_structure->ar_sha,arp_interface->addr,sizeof(uint8_t)*6);
				memcpy(arp_reply_structure->ar_tha,eth_header->ether_shost,sizeof(uint8_t)*6);
				arp_reply_structure->ar_sip = arp_interface->ip;
				arp_reply_structure->ar_tip = arp_header->ar_sip;
				/* Now send the packet */
				/* Beaware of the size of the frame, it should not be sizeof(arp_reply_packet)
				But the size used below */
				sr_send_packet(sr,arp_reply_packet,sizeof(sr_ethernet_hdr_t)+1500,interface);
			}
			else if( op_code == 2 )
			{
				/* ARP Reply */
				uint8_t* MAC = (uint8_t*)malloc(sizeof(uint8_t)*6);
				uint32_t IP;
				memcpy(MAC,arp_header->ar_sha,sizeof(uint8_t)*6);
				IP = arp_header->ar_sip;
				struct sr_arpreq* queue = sr_arpcache_insert(&sr->cache,MAC,IP);
				if( queue == NULL )
				{
					assert(queue!=NULL);
				}
				else
				{
					struct sr_packet* packet_i = queue->packets;
					while( packet_i!= NULL )
					{
						sr_ethernet_hdr_t* head = (sr_ethernet_hdr_t*)(packet_i->buf);
						memcpy(head->ether_dhost,MAC,sizeof(uint8_t)*6);
						sr_send_packet(sr,packet_i->buf,packet_i->len,packet_i->iface);
						packet_i = packet_i->next;
					}
					sr_arpreq_destroy(&sr->cache,queue);
				}
			}
		}
	}
}/* end sr_ForwardPacket */
