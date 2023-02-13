
/**
  ******************************************************************************
  * @file    layer3_netw.h
  * @author  Yassine Lambarki
  * @date    18-December-2020
  * @brief   Header file
  *           
  ******************************************************************************  
  */

#include <netinet/ip.h>

/**
  * @struct
  * @brief arp header
  */
typedef struct arp_hdr {
	u_int16_t htype;    /* Hardware Type           */
	u_int16_t ptype;    /* Protocol Type           */
	u_char hlen;        /* Hardware Address Length */
	u_char plen;        /* Protocol Address Length */
	u_int16_t oper;     /* Operation Code          */
	u_char sha[6];      /* Sender hardware address */
	u_char spa[4];      /* Sender IP address       */
	u_char tha[6];      /* Target hardware address */
	u_char tpa[4];      /* Target IP address       */
}arp_hdr;

/**
  * @brief			process arp header and move to next layer/protoc
  * @param			arp_hdr the arp header
  * @param			u_char* body of the packet
  * @param			int  exploring size counter 
  * @param			u_char  verbosity
  * @retval			None 
  */
void arp_inspector(struct arp_hdr *, const u_char *, int, u_char );
/**
  * @brief			process ip header and move to next layer/prot
  * @param			ip the ip header
  * @param			u_char* body of the packet
  * @param			int  exploring size counter 
  * @param			u_char  verbosity
  * @retval			None 
  */
void iphdr_inspector(struct ip *, const u_char *, int, u_char );
