/**
  ******************************************************************************
  * @file    layer7_app.h
  * @author  Yassine Lambarki
  * @date    18-December-2020
  * @brief   Header file .
  *           
  ******************************************************************************  
  */

/**
  * @struct
  * @brief dns header
  */

struct dnshdr
{
	u_int16_t query_id;
	u_int16_t flags;
	u_int16_t quest_count;
	u_int16_t answ_count;
	u_int16_t auth_count;
	u_int16_t add_count;
};

/**
  * @struct
  * @brief bootp header
  */
struct bootphdr
{
	u_int8_t msg_type;
	u_int8_t hrdwr_type;
	u_int8_t hrdwr_addr_length;
	u_int8_t hops;
	u_int32_t trans_id;
	u_int16_t num_sec;
	u_int16_t flags;
	struct in_addr ciaddr;
	struct in_addr yiaddr;
	struct in_addr siaddr;
	struct in_addr giaddr;
	u_char hrdwr_caddr[16];
	u_char srv_name[64];
	u_char bpfile_name[128];
	u_int32_t magic_cookie;
};

/**
  * @brief			process telnet protocol header and show info
  * @retval			None 
  */
void telnet_inspector(const u_char *, int, int, u_char);

/**
  * @brief			process imap protocol header and show info
  * @retval			None 
  */
void imap_inspector(const u_char *, int, int, u_char);

/**
  * @brief			process smtp protocol header and show info
  * @retval			None 
  */
void smtp_inspector(const u_char *, int, int, u_char);

/**
  * @brief			process pop protocol header and show info
  * @retval			None 
  */
void pop_inspector(const u_char *, int, int, u_char);

/**
  * @brief			process ftp protocol header and show info
  * @retval			None 
  */
void ftp_inspector(const u_char *, int, int, u_char);

/**
  * @brief			process http protocol header and show info
  * @retval			None 
  */
void http_inspector(const u_char *, int, int, u_char);

/**
  * @brief			process bootp protocol header and show info
  * @retval			None 
  */
void bootp_inspector(struct bootphdr *, const u_char *, int, int, u_char);

/**
  * @brief			process dns protocol header and show info
  * @retval			None 
  */
void dns_inspector(struct dnshdr *, const u_char *, int, int, u_char);
