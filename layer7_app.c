/**
 ******************************************************************************
* @file    layer7_app.c
* @author  Yassine Lambarki
* @date    18-December-2020
* @brief   This file analyses the information of the application layer 
* 		  contained in the frame and prcesses them .
*           
******************************************************************************  
*/

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <pcap.h>
#include <netinet/in.h>
#include <ctype.h>

#include "layer7_app.h"
#include "verbosity.h"
#include "color.h"

void telnet_inspector(const u_char *the_bd, int sz, int data_sz, u_char verbosity)
{
	int i = sz;
	int init = 1; 
	if (verbosity & (VRB_LO))
	{
		printf(" (TELNET) ");
	}
	if (verbosity & (VRB_HI|VRB_MDL))
	{
		printf("\n-----------------------TELNET\n");
	}
	if (verbosity & (VRB_HI))
	{
		while (i < data_sz + sz)
		{
			if (the_bd[i] == 255)
			{
				i++;
				while (the_bd[i] != 255 && i < data_sz + sz)
				{
					switch (the_bd[i])
					{
					case 0:
						printf("\n\tSubcommand:  transmission ");
						break;
					case 1:
						printf("\n\tSubcommand: Echo ");
						break;
					case 2:
						printf("\n\tSubcommand: Reconnection ");
						break;
					case 3:
						printf("\n\tSubcommand: Suppress go ahead ");
						break;
					case 4:
						printf("\n\tSubcommand: Approx message sz negotation ");
						break;
					case 5:
						printf("\n\tSubcommand: Status ");
						break;
					case 6:
						printf("\n\tSubcommand: Timing mark ");
						break;
					case 7:
						printf("\n\tSubcommand: Remote controlled transmition and echo");
						break;
					case 8:
						printf("\n\tSubcommand: Backspace ");
						break;
					case 9:
						printf("\n\tSubcommand: Horizontal Tab ");
						break;
					case 10:
						printf("\n\tSubcommand: Line Feed ");
						break;
					case 11:
						printf("\n\tSubcommand: Vertical Tab");
						break;
					case 12:
						printf("\n\tSubcommand: Form Feed ");
						break;
					case 13:
						printf("\n\tSubcommand: Carriage Return ");
						break;
					case 14:
						printf("\n\tSubcommand: Output vertical tabstops ");
						break;
					case 15:
						printf("\n\tSubcommand: Output vertical tab disposition ");
						break;
					case 16:
						printf("\n\tSubcommand: Output linefeed disposition ");
						break;
					case 17:
						printf("\n\tSubcommand: Extended ASCII ");
						break;
					case 18:
						printf("\n\tSubcommand: Logout ");
						break;
					case 19:
						printf("\n\tSubcommand: Byte macro ");
						break;
					case 20:
						printf("\n\tSubcommand: Data entry terminal ");
						break;
					case 21:
						printf("\n\tSubcommand: SUPDUP ");
						break;
					case 22:
						printf("\n\tSubcommand: SUPDUP output ");
						break;
					case 23:
						printf("\n\tSubcommand: Send location ");
						break;
					case 24:
						printf("\n\tSubcommand: Terminal type ");
						break;
					case 25:
						printf("\n\tSubcommand: End of record ");
						break;
					case 26:
						printf("\n\tSubcommand: TACACS user identification ");
						break;
					case 27:
						printf("\n\tSubcommand: Output marking");
						break;
					case 28:
						printf("\n\tSubcommand: Terminal location number ");
						break;
					case 29:
						printf("\n\tSubcommand: Telnet 3270 regime ");
						break;
					case 30:
						printf("\n\tSubcommand: X.3 PAD ");
						break;
					case 31:
						printf("\n\tSubcommand: Window sz ");
						break;
					case 32:
						printf("\n\tSubcommand: Terminal speed ");
						break;
					case 33:
						printf("\n\tSubcommand: Remote flow control ");
						break;
					case 34:
						printf("\n\tSubcommand: Linemode ");
						break;
					case 35:
						printf("\n\tSubcommand: X display location");
						break;
					case 36:
						printf("\n\tSubcommand: Environment option ");
						break;
					case 38:
						printf("\n\tSubcommand: Encryption option ");
						break;
					case 39:
						printf("\n\tSubcommand: New environment option ");
						break;
					case 240:
						printf("Command :Suboption End (%d)", the_bd[i]);
						break;
					case 241:
						printf("Command :No Operation (%d)", the_bd[i]);
						break;
					case 242:
						printf("Command :Data Mark (%d)", the_bd[i]);
						break;
					case 244:
						printf("Command :Intrerrupt Process(%d)", the_bd[i]);
						break;
					case 245:
						printf("Command :Abort Output (%d)", the_bd[i]);
						break;
					case 246:
						printf("Command :Are You There (%d)", the_bd[i]);
						break;
					case 247:
						printf("Command :Erase Character (%d)", the_bd[i]);
						break;
					case 248:
						printf("Command :Erase Line (%d)", the_bd[i]);
						break;
					case 249:
						printf("Command :Go Ahead (%d)", the_bd[i]);
						break;
					case 250:
						printf("Command :Suboption (%d)", the_bd[i]);
						break;
					case 251:
						printf("Command :WILL (%d)", the_bd[i]);
						break;
					case 252:
						printf("Command :WON'T (%d)", the_bd[i]);
						break;
					case 253:
						printf("Command :DO (%d)", the_bd[i]);
						break;
					case 254:
						printf("Command :DON'T (%d)", the_bd[i]);
						break;
					default:
						printf("%c", the_bd[i]);
						break;
					}
					i++;
				}
				printf("\n");
			}

			else
			{
				if (init == 1)
				{
					printf("Data : ");
					init = 0;
				}
				if (the_bd[i - 1] == '\n')
					printf("\nData : ");
				printf("%c", the_bd[i]);
				i++;
			}
		}
		printf("\n");
	}
}

void imap_inspector(const u_char *the_bd, int sz, int data_sz, u_char verbosity)
{
	int i;
	if (verbosity & (VRB_LO))
	{
		printf(" (IMAP)");
	}

	if (verbosity & (VRB_HI|VRB_MDL))
	{
		printf("\n-----------------------Internet Message Access Protocol\n");
	}

	if (verbosity & (VRB_HI))
	{
		printf("Ligne : ");
		for (i = sz; i < sz + data_sz; ++i)
		{
			if (the_bd[i - 1] == '\n')
				printf("\nLine : ");
			if (isprint(the_bd[i]) || the_bd[i] == '\t' || the_bd[i] == '\r')
				printf("%c", the_bd[i]);
		}
	}
}

void smtp_inspector(const u_char *the_bd, int sz, int data_sz, u_char verbosity)
{
	int i;
	if (verbosity & (VRB_LO))
	{
		printf(" (SMTP)");
	}
	if (verbosity & (VRB_HI|VRB_MDL))
	{
		printf("\n-----------------------Simple Mail Transfer Protocol\n");
	}
	if (verbosity & (VRB_HI))
	{
		for (i = sz; i < sz + data_sz; ++i)
		{
			if (isprint(the_bd[i]) || the_bd[i] == '\n' || the_bd[i] == '\t' || the_bd[i] == '\r')
				printf("%c", the_bd[i]);
			else
				printf(".");
		}
	}
}

void pop_inspector(const u_char *the_bd, int sz, int data_sz, u_char verbosity)
{
	int i;
	if (verbosity & (VRB_LO))
	{
		printf(" (POP)\n");
	}
	if (verbosity & (VRB_MDL|VRB_HI))
	{
		printf("\n-----------------------Post Office Protocol\n");
	}
	if (verbosity & (VRB_HI))
	{
		for (i = sz; i < sz + data_sz; ++i)
		{
			if (isprint(the_bd[i]) || the_bd[i] == '\n' || the_bd[i] == '\t' || the_bd[i] == '\r')
				printf("%c", the_bd[i]);
			else
				printf(".");
		}
	}
}

void ftp_inspector(const u_char *the_bd, int sz, int data_sz, u_char verbosity)
{
	int i;
	if (verbosity & (VRB_LO))
	{
		printf(" (FTP)");
	}
	if (verbosity & (VRB_HI|VRB_MDL))
	{
		printf("\n-----------------------File Transfer Protocol\n");
	}
	if (verbosity & (VRB_HI))
	{
		for (i = sz; i < sz + data_sz; ++i)
		{
			if (the_bd[i - 1] == '\n')
				printf("\t\t\t");
			if (isprint(the_bd[i]) || the_bd[i] == '\n' || the_bd[i] == '\t' || the_bd[i] == '\r')
				printf("%c", the_bd[i]);
			else
				printf(".");
		}
	}
}

void http_inspector(const u_char *the_bd, int sz, int data_sz, u_char verbosity)
{
	int i;
	if (verbosity & (VRB_LO))
	{
		printf(" (HTTP)");
	}
	if (verbosity & (VRB_HI|VRB_MDL))
	{
		printf("\n-----------------------Hypertext Transfer Protocol\n");
	}
	if (verbosity & (VRB_HI))
	{
		for (i = sz; i < sz + data_sz; ++i)
		{
			if (isprint(the_bd[i]) || the_bd[i] == '\n' || the_bd[i] == '\t' || the_bd[i] == '\r')
				printf("%c", the_bd[i]);
			else
				printf(".");
		}
	}
}

void bootp_inspector(struct bootphdr *bootp, const u_char *the_bd, int sz, int data_sz, u_char verbosity)
{
	int i, j, l, heure, min, sec;
	u_int32_t tmp;
	bootp = (struct bootphdr *)(the_bd + sz);

	if (verbosity & (VRB_MDL | VRB_HI))
	{
		printf("\n------------------------BOOTP");
		printf("\nMessage type : ");
		switch (bootp->msg_type)
		{
		case 1:
			printf("Boot Request (%i) \n", bootp->msg_type);
			break;
		case 2:
			printf("Boot Reply (%i) \n", bootp->msg_type);
			break;
		default:
			printf("Unknown (%i) \n", bootp->msg_type);
			break;
		}

		printf("Hardware type : ");
		switch (bootp->hrdwr_type)
		{
		case 1:
			printf("Ethernet (0x%02x) ", bootp->hrdwr_type);
			break;
		case 6:
			printf("IEEE 802 (0x%02x) ", bootp->hrdwr_type);
			break;
		case 18:
			printf("Fibre channel (0x%02x) ", bootp->hrdwr_type);
			break;
		case 20:
			printf("Serial line (0x%02x) ", bootp->hrdwr_type);
			break;
		default:
			printf("Unknown (0x%02x) ", bootp->hrdwr_type);
			break;
		}
		printf("\n");
		if (verbosity & (VRB_HI))
		{

			printf("Hardware address length : %d bytes\n", bootp->hrdwr_addr_length);
			printf("Hops : %d\n", bootp->hops);
			printf("Transaction ID : 0x%08x\n", ntohl(bootp->trans_id));
			printf("Seconds elapsed : %d\n", ntohs(bootp->num_sec));
			printf("Bootp flags : 0x%04x\n", bootp->flags);
			printf("Client IP address : %s\n", inet_ntoa(bootp->ciaddr));
			printf("Your (client) IP address : %s\n", inet_ntoa(bootp->yiaddr));
			printf("Next server IP address : %s\n", inet_ntoa(bootp->siaddr));
			printf("Relay agent IP address : %s\n", inet_ntoa(bootp->giaddr));

			if (bootp->hrdwr_addr_length == 6)
			{
				printf("Client MAC address : %02x:%02x:%02x:%02x:%02x:%02x\n",
					   bootp->hrdwr_caddr[0], bootp->hrdwr_caddr[1], bootp->hrdwr_caddr[2],
					   bootp->hrdwr_caddr[3], bootp->hrdwr_caddr[4], bootp->hrdwr_caddr[5]);
				printf("Client hardware address padding : ");
				for (i = 6; i < 16; i++)
				{
					printf("%02x", bootp->hrdwr_caddr[i]);
				}
				printf("\n");
			}
			else
			{
				printf("Client hardware address unknown : ");
				for (i = 0; i < 16; i++)
				{
					printf("%02x", bootp->hrdwr_caddr[i]);
				}
				printf("\n");
			}

			printf("Server host name : ");
			if (bootp->srv_name[0] != 0)
			{
				for (i = 0; i < 64 && bootp->srv_name[i] != 0; i++)
				{
					printf("%c", bootp->srv_name[i]);
				}
				printf("\n");
			}
			else
			{
				printf("not given\n");
			}

			printf("Boot file name : ");
			if (bootp->bpfile_name[0] != 0)
			{
				for (i = 0; i < 128 && bootp->bpfile_name[i] != 0; i++)
				{
					printf("%c", bootp->bpfile_name[i]);
				}
				printf("\n");
			}
			else
			{
				printf("not given\n");
			}
			// capture dhcp
			if (ntohl(bootp->magic_cookie) == 0x63825363)
			{
				printf("Magic cookie : DHCP\n");
				for (i = sizeof(struct bootphdr) + sz; i < (data_sz + sz) && the_bd[i] != 255; i++)
				{
					printf("Option: (%i) ", (int)the_bd[i]);
					switch ((int)the_bd[i])
					{
					case 1:
						printf("Subnet mask ");
						i++;
						l = (int)the_bd[i];
						i++;
						printf("%d.%d.%d.%d", the_bd[i], the_bd[i + 1], the_bd[i + 2], the_bd[i + 3]);
						printf("\n\tlenght %i\n", l);
						i += l - 1;
						break;
					case 50:
						printf("Requested IP address ");
						i++;
						l = (int)the_bd[i];
						i++;
						printf("%d.%d.%d.%d", the_bd[i], the_bd[i + 1], the_bd[i + 2], the_bd[i + 3]);
						printf("\n\tlenght %i\n", l);
						i += l - 1;
						break;
					case 51:
						i++;
						l = (int)the_bd[i];
						i++;
						tmp = ntohl(*(u_int32_t *)(the_bd + i));
						;
						heure = tmp / 3600;
						min = (tmp - heure * 3600) / 60;
						sec = (tmp - heure * 3600) % 60;
						printf("IP address lease time (%ds) %i hours ,%i minutes, %i seconds ", tmp, heure, min, sec);
						printf("\n\tlenght %i\n", l);
						i += l - 1;
						break;
					case 53:
						printf("DHCP message type ");
						i++;
						l = (int)the_bd[i];
						i++;
						switch ((int)the_bd[i])
						{
						case 1:
							printf("(DISCOVER)");
							break;
						case 2:
							printf("(OFFER)");
							break;
						case 3:
							printf("(REQUEST)");
							break;
						case 4:
							printf("(DECLINE)");
							break;
						case 5:
							printf("(ACK)");
							break;
						case 6:
							printf("(NACK)");
							break;
						case 7:
							printf("(RELEASE)");
							break;
						default:
							printf("(UNKNOWN)");
							break;
						}
						printf("\n\tlenght %i\n", l);
						i += l - 1;
						break;
					case 54:
						i++;
						l = (int)the_bd[i];
						i++;
						printf("DHCP server identifier ");
						printf("%d.%d.%d.%d", the_bd[i], the_bd[i + 1], the_bd[i + 2], the_bd[i + 3]);
						printf("\n\tlenght %i\n", l);
						i += l - 1;
						break;
					case 55:
						printf("Parameter Request List \n");
						i++;
						l = (int)the_bd[i];
						for (j = 0; j < (int)the_bd[i]; j++)
						{
							printf("\tParameter Request List Item: (%i)", the_bd[i + j + 1]);
							switch (the_bd[i + j + 1])
							{
							case 1:
								printf(" Subnet Mask");
								break;
							case 3:
								printf(" Router");
								break;
							case 6:
								printf(" Domain Name Server");
								break;
							case 42:
								printf(" Network Time Protocol Servers");
								break;
							default:
								printf(" Unknown");
								break;
							}
							printf("\n");
						}
						i += ((int)the_bd[i]);
						printf("\tlenght %i\n", l);
						break;
					case 58:
						i++;
						l = (int)the_bd[i];
						i++;
						tmp = ntohl(*(u_int32_t *)(the_bd + i));
						heure = tmp / 3600;
						min = (tmp - heure * 3600) / 60;
						sec = (tmp - heure * 3600) % 60;
						printf("Renewal Time Value (%ds) %i hours ,%i minutes, %i seconds ", tmp, heure, min, sec);
						i += l - 1;
						printf("\n\tlenght %i\n", l);
						break;
					case 59:
						i++;
						l = (int)the_bd[i];
						i++;
						tmp = ntohl(*(u_int32_t *)(the_bd + i));
						heure = tmp / 3600;
						min = (tmp - heure * 3600) / 60;
						sec = (tmp - heure * 3600) % 60;
						printf("Rebinding Time Value (%ds) %i hours ,%i minutes, %i seconds ", tmp, heure, min, sec);
						i += l - 1;
						printf("\n\tlenght %i\n", l);
						break;
					case 61:
						i++;
						l = (int)the_bd[i];
						i++;
						printf("Hardware type 0x%02x\n", the_bd[i]);
						if ((int)the_bd[i] == 1)
						{
							printf("\tClient identifier  %02x:%02x:%02x:%02x:%02x:%02x",
								   the_bd[i + 1], the_bd[i + 2], the_bd[i + 3],
								   the_bd[i + 4], the_bd[i + 5], the_bd[i + 6]);
						}
						else
						{
							printf("unknown identifier");
						}
						printf("\n\tlenght %i\n", l);
						i += l - 1;
						break;
					default:
						printf("Unknown (0x%02x)\n", the_bd[i]);
						i++;
						printf("\t\t\t\tLength : %d bytes\n", (int)the_bd[i]);
						printf("\t\t\t\tValue : 0x");
						for (j = 0; j < (int)the_bd[i]; j++)
						{
							printf("%02x", the_bd[i + j + 1]);
						}
						printf("\n");
						i += j;
						break;
					}

					if (the_bd[i + 1] == 255)
					{
						printf("Option :(255) End");
					}
				}
			}
		}
	}

	// VRB_LO , ex : (BOOTP)  (DHCP) Discover
	if (verbosity & (VRB_LO | VRB_MDL))
	{
		if (verbosity & (VRB_LO))
			printf(" (BOOTP) ");
		{
			for (i = sizeof(struct bootphdr) + sz; i < (data_sz + sz) && the_bd[i] != 0xff; i++)
			{
				switch ((int)the_bd[i])
				{
				case 53:
					printf(" (DHCP) ");
					i++;
					l = (int)the_bd[i];
					i++;
					switch ((int)the_bd[i])
					{
					case 1:
						printf("Discover");
						break;
					case 2:
						printf("Offer");
						break;
					case 3:
						printf("Request");
						break;
					case 4:
						printf("Decline");
						break;
					case 5:
						printf("Ack");
						break;
					case 6:
						printf("Nack");
						break;
					case 7:
						printf("release");
						break;
					default:
						printf("Unknown");
						break;
					}
					i += l - 1;
					break;
				default:
					i++;
					l = (int)the_bd[i];
					i += l - 1;
					break;
				}
			}
		}
		printf("\n");
	}
}

void dns_inspector(struct dnshdr *dnshdr, const u_char *packet, int sz, int data_sz, u_char verbosity)
{
	int i, j = 0, k, l = 0, questions, answers;
	u_int16_t *type, *class, *d_size;
	u_int32_t *ttl;
	dnshdr = (struct dnshdr *)(packet + sz);
	questions = ntohs(dnshdr->quest_count);
	answers = ntohs(dnshdr->answ_count);

	// Header start
	if (verbosity & (VRB_MDL))
		printf(" (DNS)");
	if (verbosity & (VRB_HI|VRB_MDL))
		printf("\n------------------------Domain Name System\n");

	if (verbosity & (VRB_MDL | VRB_HI))
	{
		if (verbosity & (VRB_HI))
		{
			printf("Transaction id : 0x%04x\n", ntohs(dnshdr->query_id));
			printf("Flags : 0x%04x\n", ntohs(dnshdr->flags));
			printf("Questions : %d\n", ntohs(dnshdr->quest_count));
			printf("Answer RRs : %d\n", ntohs(dnshdr->answ_count));
			printf("Authority RRs : %d\n", ntohs(dnshdr->auth_count));
			printf("Additional RRs : %d\n", ntohs(dnshdr->add_count));
		}
		if (questions > 0)
		{
			if (verbosity & (VRB_HI))
				printf("\t\t\tQueries\n");
			if (verbosity & (VRB_MDL))
				printf("||Queries  ");
			l = j;
			for (k = 0; k < questions; k++)
			{
				printf("Name: ");
				for (i = sizeof(struct dnshdr) + sz + j; i < data_sz + sz && packet[i] != 0x00; i++)
				{
					if (isprint(packet[i]))
						printf("%c", packet[i]);
					else
						printf(".");
				}

				if (verbosity & (VRB_HI))
					printf("\n");
				printf(" [Name lenght]: %li   ", i - sz - j - sizeof(struct dnshdr));
				j = i + 1;
				if (verbosity & (VRB_HI))
					printf("\n");

				type = (u_int16_t *)(packet + j); 
				j += 2;
				class = (u_int16_t *)(packet + j);
				switch (ntohs(*type))
				{
				case 1:
					printf("Type :A (Address record) (%i) ", ntohs(*type));
					break;
				case 2:
					printf("Type :NS (Authorative Name Server)(%i) ", ntohs(*type));
					break;
				case 28:
					printf("Type :AAAA (IPv6 address record) (%i) ", ntohs(*type));
					break;
				case 5:
					printf("Type :CNAME (Canonical name record) (%i) ", ntohs(*type));
					break;
				case 12:
					printf("Type :PTR (domain name PoinTeR)(%i) ", ntohs(*type));
					break;
				case 15:
					printf("Type :MX (Mail eXchange )(%i) ", ntohs(*type));
					break;
				case 6:
					printf("Type :SOA (Start of authority record)(%i) ", ntohs(*type));
					break;
				case 16:
					printf("Type :TXT (Text Strings)(%i) ", ntohs(*type));
					break;
				case 33:
					printf("Type :SRV (Server Selection)(%i) ", ntohs(*type));
					break;
				default:
					printf("Type :Unknown ");
					break;
				}
				if (verbosity & (VRB_HI))
					printf("\n");

				printf("Class : ");
				switch (ntohs(*class))
				{
				case 0:
					printf("Reserved (0x%04x) ", ntohs(*class));
					break;
				case 1:
					printf("IN (0x%04x) ", ntohs(*class));
					break;
				case 2:
					printf("Unassigned (0x%04x) ", ntohs(*class));
					break;
				case 3:
					printf("Chaos (0x%04x) ", ntohs(*class));
					break;
				case 4:
					printf("Hesiod(0x%04x) ", ntohs(*class));
					break;
				default:
					printf("Unknown(0x%04x) ", ntohs(*class));
					break;
				}
				if (verbosity & (VRB_HI))
					printf("\n");
			}
		}

		if (answers > 0)
		{
			if (verbosity & (VRB_HI))
			{
				printf("\t\t\tAnswers\n");
				printf("Name: ");
				for (i = sizeof(struct dnshdr) + sz + l; i < data_sz + sz && packet[i] != 0x00; i++)
				{
					if (packet[i] == 0x03)
						printf(".");
					else if (packet[i] != 0x0c)
					{
						if (isprint(packet[i]))
							printf("%c", packet[i]);
						else
							printf(".");
					}
				}
				printf("\n");
			}
			if (verbosity & (VRB_MDL))
				printf("||Answers  ");

			for (k = 0; k < answers; k++)
			{
				j += 4;
				type = (u_int16_t *)(packet + j);
				j += 2;
				class = (u_int16_t *)(packet + j);
				j += 2;
				ttl = (u_int32_t *)(packet + j);
				j += 4;
				d_size = (u_int16_t *)(packet + j);
				j += 2;
				switch (ntohs(*type))
				{
				case 1:
					printf("Type :A (Address record) (%i) ", ntohs(*type));
					break;
				case 28:
					printf("Type :AAAA (IPv6 address record) (%i) ", ntohs(*type));
					break;
				case 5:
					printf("Type :CNAME (Canonical name record) (%i) ", ntohs(*type));
					break;
				case 12:
					printf("Type :PTR (domain name PoinTeR) (%i) ", ntohs(*type));
					break;
				case 15:
					printf("Type :MX (Mail exchange record)(%i) ", ntohs(*type));
					break;
				case 2:
					printf("Type :NS (Authorative Name Server)(%i) ", ntohs(*type));
					break;
				case 6:
					printf("Type :SOA (Start of authority record)(%i) ", ntohs(*type));
					break;
				case 16:
					printf("Type :TXT (Text record)(%i) ", ntohs(*type));
					break;
				default:
					printf("Type :Unknown ");
					break;
				}
				if (verbosity & (VRB_HI))
					printf("\n");

				switch (ntohs(*class))
				{
				case 0:
					printf("Class :Reserved (0x%04x) ", ntohs(*class));
					break;
				case 1:
					printf("Class :IN (0x%04x) ", ntohs(*class));
					break;
				case 2:
					printf("Class :Unassigned (0x%04x) ", ntohs(*class));
					break;
				case 3:
					printf("Class :Chaos (0x%04x) ", ntohs(*class));
					break;
				case 4:
					printf("Class :Hesiod(0x%04x) ", ntohs(*class));
					break;
				default:
					printf("Class :Unknown(0x%04x) ", ntohs(*class));
					break;
				}
				if (verbosity & (VRB_HI))
				{
					printf("\n");
					printf("Time to live %d\n", ntohl(*ttl));
					printf("Data length %d\n", ntohs(*d_size));
					if (ntohs(*type) == 1)
					{
						printf("Address%d.%d.%d.%d\n", packet[j], packet[j + 1], packet[j + 2], packet[j + 3]);
					}
					if (ntohs(*type) == 28)
					{
						printf("Address %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
							   ntohs(*(u_int16_t *)(packet + j)),
							   ntohs(*(u_int16_t *)(packet + j + 2)),
							   ntohs(*(u_int16_t *)(packet + j + 4)),
							   ntohs(*(u_int16_t *)(packet + j + 6)),
							   ntohs(*(u_int16_t *)(packet + j + 8)),
							   ntohs(*(u_int16_t *)(packet + j + 10)),
							   ntohs(*(u_int16_t *)(packet + j + 12)),
							   ntohs(*(u_int16_t *)(packet + j + 14)));
					}
					else
					{
						for (i = 0; i < ntohs(*d_size); ++i)
						{
							if (isprint(packet[j + i]))
								printf("%c", packet[j + i]);
							else
								printf(".");
						}
						printf("\n");
					}
					j = j + ntohs(*d_size) - 2;
				}
			}

			if (verbosity & (VRB_HI))
				printf("\n");
		}
	}

	if (verbosity & (VRB_LO))
	{
		printf(" (DNS)  ");
		if (answers > 0 && questions > 0)
			printf("Query & Response");

		else if (questions > 0)
		{
			printf("Query");
		}
		else if (answers > 0)
		{
			printf("Response");
		}
		printf("\n");
	}
}
