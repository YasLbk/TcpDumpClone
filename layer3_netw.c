/**
  ******************************************************************************
  * @file    layer3_netw.c
  * @author  Yassine Lambarki
  * @date    18-December-2020
  * @brief   This file analyses the information of the network layer 
  * 		  contained in the frame and prcesses them .
  *           
  ******************************************************************************  
  */

#include <sys/socket.h> 
#include <netinet/in.h>
#include <arpa/inet.h>

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "layer3_netw.h"
#include "layer4_tp.h"
#include "verbosity.h"
#include "sctp.h"
#include "color.h"


void iphdr_inspector(struct ip *ip, const u_char *body, int size, u_char verbose)
{
	struct icmp *icmp = NULL;
	struct tcphdr *tcphdr = NULL;
	struct udphdr *udphdr = NULL;
	struct sctphdr *sctphdr = NULL;
	ip = (struct ip *)(body + size);
	int ip_sz = 4 * ip->ip_hl; //IP Header lenght in bytes
	size += sizeof(struct ip); //

	if (verbose & (VRB_LO))
	{
		printf("Src: %s > ", inet_ntoa(ip->ip_src));
		printf("Dst: %s ", inet_ntoa(ip->ip_dst));
	}
	if (verbose & (VRB_MDL | VRB_HI))
	{
		printf("\n--------Internet Protocol Version %d, ", ip->ip_v);
		printf("Src: %s, ", inet_ntoa(ip->ip_src));
		printf("Dst: %s ", inet_ntoa(ip->ip_dst));
	}
	if (verbose & (VRB_MDL))
	{
		printf(" \n\tIHL: %d bytes\n", (ip->ip_hl) * 4);
		printf(" \tType of service: 0x%02x\n", ip->ip_tos);
		printf(" \tTotal Lenght: %d\n", ntohs(ip->ip_len));
	}
	// Too talkative
	if (verbose & (VRB_HI))
	{
		printf("\nVersion: %d\n", ip->ip_v);
		printf("Header Length: %d bytes \n", (ip->ip_hl) * 4);
		printf("Type of service: 0x%02x\n", ip->ip_tos);
		printf("Total Lenght: %d\n", ntohs(ip->ip_len));
		printf("Identification: 0x%04x (%d)\n", ntohs(ip->ip_id), ntohs(ip->ip_id));
		printf("Flags: 0x%04x\t", ip->ip_off);
		if (ntohs(ip->ip_off) & IP_RF)
			printf("\n\tReserved bit  ");
		if (ntohs(ip->ip_off) & IP_DF)
			printf("\n\tDon't fragment ");
		if (ntohs(ip->ip_off) & IP_MF)
			printf("\n\tMore fragment ");
		if (!(ntohs(ip->ip_off) & IP_RF) && !(ntohs(ip->ip_off) & IP_DF) && !(ntohs(ip->ip_off) & IP_MF))
			printf("\n\tReserved bit: Not set \n\tDon't fragment: Not set \n\tMore fragment: Not set");
		printf("\nTime to live: %d\n", ip->ip_ttl);
		printf("Protocol: ");
		switch (ip->ip_p)
		{
		case 1:
			printf("ICMP ");
			break;
		case 6:
			printf("TCP ");
			break;
		case 17:
			printf("UDP ");
			break;
		case 132:
			printf("SCTP ");
			break;
		default:
			printf("Unknown \n");
			break;
		}
		printf("(%d)\n", ip->ip_p);
		printf("Header Checksum: 0x%04x\n", ntohs(ip->ip_sum));
		printf("Source: %s\n", inet_ntoa(ip->ip_src));
		printf("Destination: %s\n", inet_ntoa(ip->ip_dst));
	}

	// Move to next layer depending on protocol
	switch (ip->ip_p)
	{
	case 1:
		icmp_inspector(icmp, body, size, verbose);
		break;
	case 6:
		tcp_inspector(tcphdr, body, size, ntohs(ip->ip_len) - ip_sz, verbose);
		break;
	case 17:
		udp_inspector(udphdr, body, size, verbose);
		break;
	case 132:
		sctp_inspector(sctphdr, body, size, verbose);
		break;
	default:
		break;
	}
}


void arp_inspector(arp_hdr *arpheader, const u_char *body, int size, u_char verbose)
{
	int i;
	arpheader = (struct arp_hdr *)(body + size);

	// Too talkative
	if (verbose & (VRB_HI))
	{
		printf("\n--------Address Resolution Protocol \n");
		printf("Hardware type: %s\n", (ntohs(arpheader->htype) == 1) ? "Ethernet (1)" : "Unknown");
		printf("Protocol type: ");
		switch (ntohs(arpheader->ptype))
		{
		case ETHERTYPE_IP:
			printf("IPv4 (0x%04x)\n", ntohs(arpheader->ptype));
			break;
		case ETHERTYPE_IPV6:
			printf("IPv6 (0x%04x)\n", ntohs(arpheader->ptype));
			break;
		default:
			printf("Unknown\n");
			break;
		}
		printf("Hardware size: %d\n", arpheader->hlen);
		printf("Protocol size: %d\n", arpheader->plen);
		// ARP opcode (command)
		printf("Opcode: ");
		switch (ntohs(arpheader->oper))
		{
		case 1:
			printf("ARP Request (%d)\n", ntohs(arpheader->oper));
			break;
		case 2:
			printf("ARP Reply (%d)\n", ntohs(arpheader->oper));
			break;
		case 3:
			printf("RARP Request (%d)\n", ntohs(arpheader->oper));
			break;
		case 4:
			printf("RARP Reply (%d)\n", ntohs(arpheader->oper));
			break;
		case 8:
			printf("InARP Request (%d)\n", ntohs(arpheader->oper));
			break;
		case 9:
			printf("InARP Reply (%d)\n", ntohs(arpheader->oper));
			break;
		case 10:
			printf("ARP NAK (%d)\n", ntohs(arpheader->oper));
			break;
		default:
			printf("Unknown\n");
			break;
		}

		if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800)
		{
			printf("Sender MAC address: ");
			for (i = 0; i < 5; i++)
				printf("%02X:", arpheader->sha[i]);
			printf("%02X", arpheader->sha[5]);
			printf("\nSender IP address: ");
			for (i = 0; i < 3; i++)
				printf("%d.", arpheader->spa[i]);
			printf("%d", arpheader->spa[3]);
			printf("\nTarget MAC address: ");
			for (i = 0; i < 5; i++)
				printf("%02X:", arpheader->tha[i]);
			printf("%02X", arpheader->tha[5]);
			printf("\nTarget IP address: ");
			for (i = 0; i < 3; i++)
				printf("%d.", arpheader->tpa[i]);
			printf("%d", arpheader->tpa[3]);
		}
		printf("\n");
	}

	
	//For verbose 1 and 2
	if (verbose & (VRB_MDL | VRB_LO))
	{	if(verbose & VRB_LO )
			printf(" (ARP) ");
		if (verbose & (VRB_MDL))
		{
			printf("\n--------Address Resolution Protocol ");
			/*
			if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800)
			{
				printf("Sender MAC address: ");
				for (i = 0; i < 5; i++)
					printf("%02X:", arpheader->sha[i]);
				printf("%02X", arpheader->sha[5]);
				printf("\nSender IP address: ");
				for (i = 0; i < 3; i++)
					printf("%d.", arpheader->spa[i]);
				printf("%d", arpheader->spa[3]);
				printf("\nTarget MAC address: ");
				for (i = 0; i < 5; i++)
					printf("%02X:", arpheader->tha[i]);
				printf("%02X", arpheader->tha[5]);
				printf("\nTarget IP address: ");
				for (i = 0; i < 3; i++)
					printf("%d.", arpheader->tpa[i]);
				printf("%d", arpheader->tpa[3]);
			}
			printf("\t");
			*/

		}
		switch (ntohs(arpheader->oper))
		{
		case 1:
			printf("ARP Request \n");
			break;
		case 2:
			printf("ARP Reply \n");
			break;
		case 3:
			printf("RARP Request\n");
			break;
		case 4:
			printf("RARP Reply");
			break;
		case 8:
			printf("InARP Request ");
			break;
		case 9:
			printf("InARP Reply ");
			break;
		case 10:
			printf("ARP NAK ");
			break;
		default:
			printf("Unknown\n");
			break;
		}
	}
}
