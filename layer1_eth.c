/**
  ******************************************************************************
  * @file    layer1_eth.c
  * @author  Yassine Lambarki
  * @date    18-December-2020
  * @brief   This file analyses the information of the layer1 contained in the
  * 		ethernet frame.
  *           
  ******************************************************************************  
  */

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>

#include "layer3_netw.h"
#include "verbosity.h"
#include "color.h"

// Ethernet
void ethernet_inspector(struct ether_header *eth_header, const u_char *body, const struct pcap_pkthdr *header, u_char verbosity)
{
	int i, sz = 0;
	arp_hdr *arphdr = NULL;
	struct ip *iphdr = NULL;
	eth_header = (struct ether_header *)body;
	sz += sizeof(struct ether_header);

	// Ex : Ethernet II, Src: 00:07:0d:af:f4:54, Dst: ff:ff:ff:ff:ff:ff:ff
	if (verbosity & (VRB_HI | VRB_MDL))
	{
		// Ethernet light info
		printf("\nEthernet II, ");

		// Light source/dest mac address
		printf("Src: ");
		for (i = 0; i < 5; i++)
			printf("%02x:", eth_header->ether_shost[i]);
		printf("%02x, ", eth_header->ether_shost[5]);
		printf("Dst: ");
		for (i = 0; i < 6; i++)
			printf("%02x:", eth_header->ether_dhost[i]);
		printf("%02x  ", eth_header->ether_dhost[5]);
	}
	// Too much talkative
	if (verbosity & (VRB_HI))
	{
		// Destination host's informations
		printf("\nDestination: (");
		for (i = 0; i < 5; i++)
			printf("%02x:", eth_header->ether_dhost[i]);
		printf("%02x)\n", eth_header->ether_dhost[5]);

		// Source host's informations
		printf("Source: (");
		for (i = 0; i < 5; i++)
			printf("%02x:", eth_header->ether_shost[i]);
		printf("%02x)\n", eth_header->ether_shost[5]);

		// Show Type of Protocol and move to next layer
		if (ntohs(eth_header->ether_type) == ETHERTYPE_IP)
		{
			printf("Type: IPv4 (0x%04x)\n", ntohs(eth_header->ether_type));
			iphdr_inspector(iphdr, body, sz, verbosity);
		}
		else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP)
		{
			printf("Type: ARP (0x%04x)\n", ntohs(eth_header->ether_type));
			arp_inspector(arphdr, body, sz, verbosity);
		}
		else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6)
		{
			printf("Type: IPv6 (0x%04x)\n", ntohs(eth_header->ether_type));
		}
		printf("\n");
	}

	// In brief and silent movement to next layer
	if (verbosity & (VRB_LO | VRB_MDL))
	{
		if (ntohs(eth_header->ether_type) == ETHERTYPE_IP)
			iphdr_inspector(iphdr, body, sz, verbosity);
		else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP)
		{
			if (verbosity & VRB_LO)
			{
				// In case of arp and VRB_LO show @MAC
				// Light source/dest mac address
				printf("Src: ");
				for (i = 0; i < 5; i++)
					printf("%02x:", eth_header->ether_shost[i]);
				printf("%02x, ", eth_header->ether_shost[5]);
				printf("Dst: ");
				for (i = 0; i < 6; i++)
					printf("%02x:", eth_header->ether_dhost[i]);
				printf("%02x  ", eth_header->ether_dhost[5]);
			}
			arp_inspector(arphdr, body, sz, verbosity);
		}
		else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6)
			printf("Type IPv6 (0x%04x)\n", ntohs(eth_header->ether_type));
	}
}
