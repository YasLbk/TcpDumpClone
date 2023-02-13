/**
  ******************************************************************************
  * @file    layer1_eth.h
  * @author  Yassine Lambarki
  * @date    18-December-2020
  * @brief   Header file
  *           
  ******************************************************************************  
  */

#include <netinet/if_ether.h>

/**
  * @brief			callback function to handle packet's info
  * @retval			None 
  */
void pcap_handler_cb(u_char *, const struct pcap_pkthdr *, const u_char *);

/**
  * @brief			function to process first ethernet header 
  * @retval			None 
  */
void ethernet_inspector(struct ether_header *, const u_char *, const struct pcap_pkthdr *, u_char);

/**
  * @brief			error raler
  * @retval			None 
  * @remark     this function always finish with a EXIT_FAILURE
  */
void error_msg(const char *errmsg, char* file);