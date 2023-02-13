/**
  ******************************************************************************
  * @file    main.c
  * @author  Yassine Lambarki
  * @date    18-December-2020
  * @brief   main file , entry options from user , and start handling 
  * 			upcoming packets
  *           
  ******************************************************************************  
  */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

#include "layer1_eth.h"
#include "verbosity.h"
#include "color.h"

int pcounter; // packects' counter
int color;	  // colorized output

void error_msg(const char *errmsg, char *file)
{
	fprintf(stderr, "%s %s\n", errmsg, file);
	exit(EXIT_FAILURE);
}

void pcap_handler_cb(u_char *args, const struct pcap_pkthdr *header, const u_char *body)
{
	struct ether_header *eth_header = NULL;
	int i;

	// Increment packets' counter
	pcounter++;
	if (*args & VRB_LO)
	{
		printf("\n--------------------------------------------------------------------------------------------");
		printf("\n#Frame N*%d: ", pcounter);
	}
	else if (*args & VRB_MDL)
	{
		printf("\n--------------------------------------------------------------------------------------------");
		printf("\n#Frame Number %d ", pcounter);
	}

	else
	{
		// Start to show the packet
		printf("\n*****************************************Packet Number %d*************************************\n", pcounter);

		// Showing the raw packet format
		printf("\n\tRaw format :\n");
		printf("\t-----------------------------------------------------\n\t| ");

		for (i = 0; i < header->len; ++i)
		{
			if (color == 1)
				printf(CYN "%02x " RESET, body[i]);
			else
				printf("%02x ", body[i]);
			if ((i + 1) % 16 == 0)
				printf("|\n\t| ");
			if (((i + 9)) % 16 == 0)
				printf("  ");
		}
		printf("\n\t-----------------------------------------------------\n");
	}
	// Process the ethernet trame
	ethernet_inspector(eth_header, body, header, *args);
}

void usage()
{
	printf("\nusage: ./analyseur\n\t-i <interface> interface from where to capture packets\n\t-o <file> a packet file\n\t-f <BPF filter> filter \n\t-v <1|2|3>(verbosity) verbosity to show info\n\t -c colorized output in terminal\n");
}

int main(int argc, char *argv[])
{
	int verb, verbosity = VRB_HI; 
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	bpf_u_int32 net, mask; 
	pcap_t *handle;
	char c;
	char *device = NULL, *file = NULL, *filter = NULL;
	color = 0;

	// Parsing options and arguments
	while ((c = getopt(argc, argv, "i:o:f:v:uc")) != -1)
	{
		switch (c)
		{
		case 'i':
			// Specified Interface
			device = optarg;
			break;
		case 'o':
			// Specified capture file
			file = optarg;
			break;
		case 'f':
			// Specified filter
			filter = optarg;
			break;
		case 'v':
			// Specified Verbosity
			verb = atoi(optarg);
			if (verb >= 1 && verb <= 3)
				if (verb == 3)
					verbosity = VRB_HI;
				else
					verbosity = verb;
			else
				printf("You should choose a verbose between 1 and 3");
			break;
		case 'u':
			// Help/Usage function()
			usage();
			return -1;
			break;
		case 'c':
			color = 1;
			break;	
		}
	}

	// If the device isn't specified
	if (!device && !file)
	{
		// Look for a default device on which to capture
		if (!(device = pcap_lookupdev(errbuf)))
			error_msg("Couldn't find default device", device);
		printf("Capturing packets from the %s device \n", device);
	}
	

	// Determine the IPv4 network number and mask associated with the "device"
	if (pcap_lookupnet(device, &net, &mask, errbuf) == -1)
	{
		error_msg("Couldn't get netmask for device", device);
	}

	// If the file isn't specified
	if (!file)
	{
		// Obtain a packet capture handle to look at packets on the network
		if (!(handle = pcap_open_live(device, BUFSIZ, 1, 0, errbuf)))
		{
			error_msg("Couldn't open device",device);
		}
		// If a filter is specified
		if (filter)
		{
			// Compile the string "filter" into a filter program
			if (pcap_compile(handle, &fp, filter, 0, net) == -1)
			{
				error_msg("Couldn't parse filter",filter);
			}
			// Specify a filter program
			if (pcap_setfilter(handle, &fp) == -1)
			{
				error_msg("Couldn't install filter",filter);
			}
		}
	}
	else
	{
		// If a file is specified , open it
		if (!(handle = pcap_open_offline(file, errbuf)))
		{
			error_msg("Couldn't open the file",file);
		}
		printf("Capturing packets from the file %s \n", file);
	}
	// Process packets from the live capture or the specified "file" until
	// cnt packets are processed or the eof is reached
	// if null error
	pcap_loop(handle, -1, pcap_handler_cb, (u_char *)&verbosity);

	// Close the capture device or savefile
	pcap_close(handle);
	
	printf("\n\n\n\nFinished !! Thank you , Au revoir !\n");
	return 0;
}
