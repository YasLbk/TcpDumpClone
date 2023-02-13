
/**
  ******************************************************************************
  * @file    layer4_tp.c
  * @author  Yassine Lambarki
  * @date    18-December-2020
  * @brief   Header File.
  *           
  ******************************************************************************  
  */

#include <netinet/ip_icmp.h>
#include "sctp.h"

/**
  * @brief			process icmp fram and move to next layer/prot
  * @param			icmp the icmp header
  * @param			u_char* body of the frame
  * @param			int  exploring size counter 
  * @param			u_char  verbosity
  * @retval			None 
  */
void icmp_inspector(struct icmp * , const u_char *, int, u_char  );
/**
  * @brief			process tcp fram and move to next layer/prot
  * @param			tcphdr the tcp header
  * @param			u_char* body of the frame
  * @param			int  exploring size counter 
  * @param			int  size of data
  * @param			u_char  verbosity
  * @retval			None 
  */
void tcp_inspector(struct tcphdr *, const u_char *, int, int, u_char);
/**
  * @brief			process sctp fram and move to next layer/prot
  * @param			sctphdr the sctp header
  * @param			u_char* body of the frame
  * @param			int  exploring size counter 
  * @param			u_char  verbosity
  * @retval			None 
  */
void sctp_inspector(struct sctphdr *, const u_char *, int, u_char);
/**
  * @brief			process udp fram and move to next layer/prot
  * @param			udphdr the udp header 
  * @param			u_char* body of the frame
  * @param			int  exploring size counter 
  * @param			u_char  verbosity
  * @retval			None 
  */
void udp_inspector(struct udphdr *, const u_char *, int, u_char);
