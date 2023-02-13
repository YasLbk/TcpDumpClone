/**
******************************************************************************
* @file    layer4_tp.c
* @author  Yassine Lambarki
* @date    18-December-2020
* @brief   This file analyses the information of the transport layer 
* 		  contained in the frame and prcesses them .
*           
******************************************************************************  
*/

#include <pcap.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "layer4_tp.h"
#include "layer7_app.h"
#include "verbosity.h"
#include "sctp.h"
#include "color.h"


void icmp_inspector(struct icmp *icmp, const u_char *thebd, int size, u_char verbosity)
{
	icmp = (struct icmp *)(thebd + size);
	if (verbosity & VRB_LO)
	{
		printf("\t(ICMP) ");
	}

	if (verbosity & (VRB_HI | VRB_MDL))
	{
		printf("\n---------------Internet Control Message Protocol\n");
	}

	if (verbosity & (VRB_MDL | VRB_HI))
	{
		printf("Type: %d ", icmp->icmp_type);
	}
	switch (icmp->icmp_type)
	{
	case 0:
		printf("(Echo Reply)");
		break;
	case 3:
		printf("(Unreach)");
		break;
	case 5:
		printf("(Redirect)");
		break;
	case 8:
		printf("(Echo Request)");
		break;
	default:
		printf("Unknown");
		break;
	}
	printf("\n");

	if (verbosity & (VRB_HI))
	{
		printf("Code: %d\n", icmp->icmp_code);
		printf("Checksum 0x%04x\n", ntohs(icmp->icmp_cksum));
		printf("Identifier (BE): %d (0x%04x)\n", ntohs(icmp->icmp_id), ntohs(icmp->icmp_id));
		printf("Identifier (LE):%d (0x%04x)\n", icmp->icmp_id, icmp->icmp_id);
		printf("Sequence number (BE): %d (0x%04x)\n", ntohs(icmp->icmp_seq), ntohs(icmp->icmp_seq));
		printf("Sequence number (LE): %d (0x%04x)\n", icmp->icmp_seq, icmp->icmp_seq);
	}
}


void tcp_inspector(struct tcphdr *tcp, const u_char *thebd, int size, int dt_sz, u_char verbosity)
{
	int noport = 1;
	int i;
	tcp = (struct tcphdr *)(thebd + size);
	int tcp_size = tcp->th_off * 4; //TCP header lenght
	int size_h;
	size_h = size + sizeof(struct tcphdr);
	size += tcp_size;

	if (verbosity & (VRB_LO))
	{
		printf(" (TCP) ");
	}
	if (verbosity & (VRB_MDL | VRB_HI))
	{
		printf("\n---------------Transmission Control Protocol\n");
		if (verbosity & (VRB_HI))
		{
			printf("Source port: %d\n", ntohs(tcp->th_sport));
			printf("Destination port: %d\n", ntohs(tcp->th_dport));
			printf("Sequence number: %u\n", ntohl(tcp->th_seq));
			printf("Acknowledgment number: %u\n", ntohl(tcp->th_ack));
		}
		//Flags
		printf("Flags: 0x%02x", tcp->th_flags);
		if (tcp->th_flags & TH_FIN)
			printf(" (FIN)");
		if (tcp->th_flags & TH_SYN)
			printf(" (SYN)");
		if (tcp->th_flags & TH_RST)
			printf(" (RST)");
		if (tcp->th_flags & TH_PUSH)
			printf(" (PSH)");
		if (tcp->th_flags & TH_ACK)
			printf(" (ACK)");
		if (tcp->th_flags & TH_URG)
			printf(" (URG)");
		if (verbosity & (VRB_HI))
		{
			printf("\n");
			printf("Window size value: %d\n", ntohs(tcp->th_win));
			printf("Checksum: 0x%04x\n", ntohs(tcp->th_sum));
			printf("Urgent pointer: %d\n", ntohs(tcp->th_urp));
			//Option analysis
			printf("Options: (%li bytes) \n", tcp_size - sizeof(struct tcphdr));
			for (i = size_h; i < size && thebd[i] != 0x00; i++)
			{
				printf("\t");
				switch (thebd[i])
				{
				case 1:
					printf("Kind: No-Operation (%d)\n", thebd[i]);
					break;
				case 2:
					printf("Kind: maximum segment size (%d)\n", thebd[i]);
					printf("\t\tLength: %d\n", thebd[i + 1]);
					printf("\t\tMSS value: %d\n", ntohs(*(u_int16_t *)(thebd + i + 2)));
					i += (int)thebd[i + 1] - 1;
					break;
				case 3:
					printf("Kind: windows scale (%d)\n", thebd[i]);
					printf("\t\tLength: %d\n", thebd[i + 1]);
					printf("\t\tShift count: %d\n", thebd[i + 2]);
					i += (int)thebd[i + 1] - 1;
					break;
				case 4:
					printf("Kind: SACK permited (%d)\n", thebd[i]);
					printf("\t\tLength: %d\n", thebd[i + 1]);
					i += (int)thebd[i + 1] - 1;
					break;
				case 8:
					printf("Kind: Timestamps(%d)\n", thebd[i]);
					printf("\t\tLength: %d\n", thebd[i + 1]);
					printf("\t\tTimestamp value %u\n", ntohl(*(u_int32_t *)(thebd + i + 2)));
					printf("\t\tTimestamp echo reply: %u\n", ntohl(*(u_int32_t *)(thebd + i + 6)));
					i += (int)thebd[i + 1] - 1;
					break;
				default:
					printf("Kind: Unknown (%d)\n", thebd[i]);
					i += (int)thebd[i + 1] - 1;
					break;
				}
			}
		}
	}

	if (verbosity & (VRB_MDL | VRB_LO))
	{
		printf("  Src port: %d   ", ntohs(tcp->th_sport));
		printf(",Dst port: %d  ", ntohs(tcp->th_dport));
		printf(",Seq: %d  ", ntohl(tcp->th_seq));
		printf(",Ack: %d  ", ntohl(tcp->th_ack));
	}

	if (verbosity & (VRB_MDL))
	{
		printf("Window size value: %d  ", ntohs(tcp->th_win));
		printf("Checksum: 0x%04x  \n", ntohs(tcp->th_sum));
	}
	// Call the function that will inspect next layer depending on the port
	if ((dt_sz - tcp_size) > 0)
	{
		switch (ntohs(tcp->source))
		{
		case 20:
			ftp_inspector(thebd, size, (int)(dt_sz - tcp_size), verbosity);
			noport = 0;
			break;
		case 21:
			ftp_inspector(thebd, size, (int)(dt_sz - tcp_size), verbosity);
			noport = 0;
			break;
		case 23:
			telnet_inspector(thebd, size, (int)(dt_sz - tcp_size), verbosity);
			noport = 0;
			break;
		case 25:
			smtp_inspector(thebd, size, (int)(dt_sz - tcp_size), verbosity);
			noport = 0;
			break;
		case 80:
			http_inspector(thebd, size, (int)(dt_sz - tcp_size), verbosity);
			noport = 0;
			break;
		case 110:
			pop_inspector(thebd, size, (int)(dt_sz - tcp_size), verbosity);
			noport = 0;
			break;
		case 143:
			imap_inspector(thebd, size, (int)(dt_sz - tcp_size), verbosity);
			noport = 0;
			break;
		}
		// avoid double entry in layer
		if (noport == 1)
		{
			switch (ntohs(tcp->dest))
			{
			case 20:
				ftp_inspector(thebd, size, (int)(dt_sz - tcp_size), verbosity);
				break;
			case 21:
				ftp_inspector(thebd, size, (int)(dt_sz - tcp_size), verbosity);
				break;
			case 23:
				telnet_inspector(thebd, size, (int)(dt_sz - tcp_size), verbosity);
				noport = 0;
				break;
			case 25:
				smtp_inspector(thebd, size, (int)(dt_sz - tcp_size), verbosity);
				break;
			case 80:
				http_inspector(thebd, size, (int)(dt_sz - tcp_size), verbosity);
				break;
			case 110:
				pop_inspector(thebd, size, (int)(dt_sz - tcp_size), verbosity);
				break;
			case 143:
				imap_inspector(thebd, size, (int)(dt_sz - tcp_size), verbosity);
				break;
			}
		}
	}
	printf("\n");
}


void sctp_inspector(struct sctphdr *sctphdr, const u_char *thebd, int size, u_char verbosity)
{
	sctphdr = (struct sctphdr *)(thebd + size);
	size += sizeof(struct sctphdr);
	u_int32_t *tsn, *adv, *payload_prot;
	u_int16_t *sid, *ssq;
	tsn = (u_int32_t *)(thebd + size);
	adv = (u_int32_t *)(thebd + size + 4);
	payload_prot = (u_int32_t *)(thebd + size + 8);
	sid = (u_int16_t *)(thebd + size + 4);
	ssq = (u_int16_t *)(thebd + size + 6);

	if (verbosity & (VRB_LO))
	{
		printf(" (SCTP) ");
	}
	if (verbosity & (VRB_HI | VRB_MDL))
	{
		printf("\n---------------Simple Mail Transfer Protocol\n");
	}

	if (verbosity & (VRB_HI))
	{
		printf("Source port: %d\n", ntohs(sctphdr->src_port));
		printf("Destination port: %d\n", ntohs(sctphdr->dest_port));
		printf("Verification tag: 0x%08x\n", ntohl(sctphdr->v_tag));
		printf("Checksum: 0x%08x\n", ntohl(sctphdr->checksum));
		printf("Chunk type: ");
		switch (sctphdr->chunk_type)
		{
		case 14:
			printf("SHUTDOWN_COMPLETE (%d) \n", sctphdr->chunk_type);
			break;
		case 8:
			printf("SHUTDOWN_ACK (%d)\n", sctphdr->chunk_type);
			break;
		case 7:
			printf("SHUTDOWN (%d)\n", sctphdr->chunk_type);
			printf("Cumulative TSN Ack %u\n", ntohl(*tsn));
			break;
		case 3:
			printf("SACK (%d)\n", sctphdr->chunk_type);
			printf("Cumulative TSN Ack %u\n", ntohl(*tsn));
			printf("Advertised receiver window credit %u\n", ntohl(*adv));
			break;
		case 0:
			printf("DATA (%d)\n", sctphdr->chunk_type);
			printf("Transmission sequence number %u\n", ntohl(*tsn));
			printf("Stream identifier 0x%04x\n", ntohs(*sid));
			printf("Stream sequence number %d\n", ntohs(*ssq));
			printf("Payload protocol identifier %u\n", ntohl(*payload_prot));
			break;
		case 11:
			printf("COOKIE_ACK (%d)\n", sctphdr->chunk_type);
			break;
		case 10:
			printf("COOKIE_ECHO (%d)\n", sctphdr->chunk_type);
			break;
		case 1:
			printf("INIT (%d)\n", sctphdr->chunk_type);
			printf("Initiate tag 0x%08x\n", ntohl(*tsn));
			printf("Advertised receiver window credit %u\n", ntohl(*adv));
			printf("Number of outbound streams %d\n", ntohs(*(u_int16_t *)(thebd + size + 8)));
			printf("Number of outbound streams %d\n", ntohs(*(u_int16_t *)(thebd + size + 10)));
			printf("Initial TSN %u\n", ntohl(*(u_int32_t *)(thebd + size + 12)));
			printf("Parameter type  0x%04x\n", ntohs(*(u_int16_t *)(thebd + size + 16)));
			printf("Parameter Lenght %d \n", ntohs(*(u_int16_t *)(thebd + size + 18)));
			printf("Supported address type (%d)", ntohs(*(u_int16_t *)(thebd + size + 20)));
			if ((ntohs(*(u_int16_t *)(thebd + size + 20))) == 5)
				printf("Ipv4 Address\n");
			else if ((ntohs(*(u_int16_t *)(thebd + size + 20))) == 6)
				printf("Ipv6 Address\n");
			else
				printf("Unknown\n");
			printf("Parameter Padding %d\n", ntohs(*(u_int16_t *)(thebd + size + 22)));
			break;
		case 2:
			printf("INIT_ACK (%d)\n", sctphdr->chunk_type);
			printf("Initiate tag 0x%08x\n", ntohl(*tsn));
			printf("Advertised receiver window credit %u\n", ntohl(*adv));
			printf("Number of outbound streams %d\n", ntohs(*(u_int16_t *)(thebd + size + 8)));
			printf("Number of outbound streams %d\n", ntohs(*(u_int16_t *)(thebd + size + 10)));
			printf("Initial TSN %u\n", ntohl(*(u_int32_t *)(thebd + size + 12)));
			printf("Parameter type  0x%04x\n", ntohs(*(u_int16_t *)(thebd + size + 16)));
			printf("Parameter Lenght %d \n", ntohs(*(u_int16_t *)(thebd + size + 18)));
			break;
		case 6:
			printf("ABORT (%d)\n", sctphdr->chunk_type);
			break;
		default:
			printf("Unknown \n");
			break;
		}
		printf("Chunk flags: 0x%02x\n", ntohs(sctphdr->chunk_flags));
		printf("Chunk length: %d\n", ntohs(sctphdr->chunk_length));
	}

	if (verbosity & (VRB_LO | VRB_MDL))
	{
		printf("  Src port: %d", ntohs(sctphdr->src_port));
		printf("  Dst port: %d", ntohs(sctphdr->dest_port));
		if (verbosity & (VRB_MDL))
		{
			printf("  Verification tag: 0x%08x", ntohl(sctphdr->v_tag));
			printf("  Checksum: 0x%08x  ", ntohl(sctphdr->checksum));
			switch (sctphdr->chunk_type)
			{
			case 14:
				printf("SHUTDOWN_COMPLETE");
				break;
			case 8:
				printf("SHUTDOWN_ACK");
				break;
			case 7:
				printf("SHUTDOWN");
				break;
			case 3:
				printf("SACK");
				break;
			case 0:
				printf("DATA");
				break;
			case 11:
				printf("COOKIE_ACK");
				break;
			case 10:
				printf("COOKIE_ECHO");
				break;
			case 1:
				printf("INIT");
				break;
			case 2:
				printf("INIT_ACK");
				break;
			case 6:
				printf("ABORT");
				break;
			default:
				printf("Unknown");
				break;
			}
			printf(" (%d)\n", sctphdr->chunk_type);
		}
		printf("\n");
	}
}


void udp_inspector(struct udphdr *udphdr, const u_char *thebd, int size, u_char verbosity)
{
	int noport = 1;
	struct dnshdr *dnshdr = NULL;
	struct bootphdr *bootphdr = NULL;
	udphdr = (struct udphdr *)(thebd + size);
	size += sizeof(struct udphdr);

	if (verbosity & (VRB_HI | VRB_MDL))
		printf("\n---------------User Diagram Protocol, ");
	if (verbosity & VRB_LO)
		printf(" (UDP) ");
	if (verbosity & (VRB_HI))
	{
		printf("\nSource Port: %d\n", ntohs(udphdr->uh_sport));
		printf("Destination Port: %d\n", ntohs(udphdr->uh_dport));
		printf("Lenght: %d\n", ntohs(udphdr->uh_ulen));
		printf("Checksum: 0x%02x\n", ntohs(udphdr->uh_sum));
	}
	if (verbosity & (VRB_MDL | VRB_LO))
	{
		printf("Src Port: %d", ntohs(udphdr->uh_sport));
		printf(", Dst port: %d", ntohs(udphdr->uh_dport));
	}
	if (verbosity & (VRB_MDL))
	{
		printf("\n\t\tLenght: %d  ", ntohs(udphdr->uh_ulen));
		printf("\n\t\tChecksum: 0x%02x\n", ntohs(udphdr->uh_sum));
	}

	// Call the function that will inspect next layer depending on the port
	switch (ntohs(udphdr->uh_sport))
	{
	case 53:
		dns_inspector(dnshdr, thebd, size, (int)(ntohs(udphdr->uh_ulen) - sizeof(struct udphdr)), verbosity);
		noport = 0;
		break;
	case 67:
		bootp_inspector(bootphdr, thebd, size, (int)(ntohs(udphdr->uh_ulen) - sizeof(struct udphdr)), verbosity);
		noport = 0;
		break;
	case 68:
		bootp_inspector(bootphdr, thebd, size, (int)(ntohs(udphdr->uh_ulen) - sizeof(struct udphdr)), verbosity);
		noport = 0;
		break;
	default:
		break;
	}

	if (noport == 1)
	{
		switch (ntohs(udphdr->uh_dport))
		{
		case 53:
			dns_inspector(dnshdr, thebd, size, (int)(ntohs(udphdr->uh_ulen) - sizeof(struct udphdr)), verbosity);
			break;
		case 67:
			bootp_inspector(bootphdr, thebd, size, (int)(ntohs(udphdr->uh_ulen) - sizeof(struct udphdr)), verbosity);
			break;
		case 68:
			bootp_inspector(bootphdr, thebd, size, (int)(ntohs(udphdr->uh_ulen) - sizeof(struct udphdr)), verbosity);
			break;
		default:
			break;
		}
	}
}
