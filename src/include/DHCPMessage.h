/*
 * Copyright (c) 2011 - 2017 Rozhuk Ivan <rozhuk.im@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */



#ifndef __DHCP_MESSAGE_H__
#define __DHCP_MESSAGE_H__


#ifndef SIZEOF
#	define SIZEOF(__X)	(sizeof(__X) / sizeof(__X[0]))
#endif


//////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////
// http://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xml#bootp-dhcp-parameters-1
//
// RFC 1542	Clarifications and Extensions for BOOTP
// RFC 2131	Dynamic Host Configuration Protocol
// RFC 2132	DHCP Options and BOOTP Vendor Extensions
// RFC 3203	DHCP reconfigure extension (FORCERENEW)
// RFC 3679	Unused DHCP Option Codes
// RFC 3942	Reclassifying DHCPv4 Options
//
// RFC 3046	DHCP Relay Agent Information Option (sub opt 1-2)
// RFC 3256	The DOCSIS (Data-Over-Cable Service Interface Specifications) Device Class DHCP (Dynamic Host Configuration Protocol) Relay Agent Information Sub-option  (add subopt 4 to RFC 3046)
// RFC 3527	Link Selection sub-option (add subopt 5 to RFC 3046)
// RFC 3993	Subscriber-ID Suboption (add subopt 6 to RFC 3046)
// RFC 4014	RADIUS Attributes Suboption (add subopt 7 to RFC 3046)
// RFC 4030	Authentication Suboption (add subopt 8 to RFC 3046)
// RFC 4243	Vendor-Specific Relay Suboption (add subopt 9 to RFC 3046)
// RFC 5010	Relay Agent Flags Suboption (add subopt 10 to RFC 3046)
// RFC 5107	Server ID Override Suboption (add subopt 11 to RFC 3046)
//
// RFC 2241	DHCP Options for Novell Directory Services
// RFC 2242	NetWare/IP Domain Name and Information
// RFC 2485	DHCP Option for The Open Group's User Authentication Protocol
// RFC 2563	DHCP Option to Disable Stateless Auto-Configuration in IPv4 Clients
// RFC 2610	DHCP Options for Service Location Protocol
// RFC 2937	The Name Service Search Option for DHCP
// RFC 2939	Procedures for New DHCP Options
// RFC 3004	The User Class Option for DHCP
// RFC 3011	The IPv4 Subnet Selection Option for DHCP
// RFC 3118	Authentication for DHCP Messages
// RFC 3442	Classless Static Route Option for DHCPv4
// RFC 3495	DHCP Option for CableLabs Clients
// RFC 3594	Security Ticket Control (add subopt to RFC 3495)
// RFC 3825	DHCP Option for Coordinate LCI
// RFC 4174	DHCP Option Number for iSNS
// RFC 4280	DHCP Options for BMCS
// RFC 4361	Node-specific Identifiers for DHCPv4
// RFC 4578	DHCP PXE Options
// RFC 4702	The DHCP Client FQDN Option
// RFC 4776	Option for Civic Addresses Configuration Information
// RFC 4833	Timezone Options for DHCP
// RFC 5071	PXELINUX Options
// RFC 5192	PAA DHCP Options
// RFC 5223	DHCP-Based LoST Discovery
// RFC 5678	Mobility Services for DCHP Options
// RFC 5859	TFTP Server Address
// RFC 7710	Captive-Portal Identification Using DHCP or Router Advertisements (RAs)
// http://www.iana.org/numbers.htm
// http://msdn.microsoft.com/en-us/library/cc227274(v=PROT.10).aspx
//////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////

//
//  DHCP Names limited to 255
//

#define DHCP_SRV_PORT		67
#define DHCP_CLI_PORT		68
#define DHCP_MIN_PACKET_LENGTH	300 /* RFC 1542 2.1 */



union dhcp_hdr_flags {
	uint16_t	flags;
	struct hdr_flags {
		uint8_t MBZ2:7;	//-- // MUST BE ZERO (reserved for future use)
		uint8_t B:1;	//C- // BROADCAST
		uint8_t MBZ1:8;	//-- // MUST BE ZERO (reserved for future use)
	} hf;
};


typedef struct dhcp_header_s {
	uint8_t		op;	/* Message op code / message type. */
	uint8_t		htype;	/* Hardware address type, see ARP section in "Assigned Numbers" RFC; e.g., '1' = 10mb ethernet. */
	uint8_t		hlen;	/* Hardware address length (e.g.  '6' for 10mb ethernet). */
	uint8_t		hops;	/* Client sets to zero, optionally used by relay agents when booting via a relay agent. */
	uint32_t	xid;	/* Transaction ID, a random number chosen by the client, used by the client and server to associate messages and responses between a client and a server. */
	uint16_t	secs;	/* Filled in by client, seconds elapsed since client began address acquisition or renewal process. */
	dhcp_hdr_flags	flags;	/* Flags. */
	uint32_t	ciaddr;	/* Client IP address; only filled in if client is in BOUND, RENEW or REBINDING state and can respond to ARP requests. */
	uint32_t	yiaddr;	/* 'your' (client) IP address. */
	uint32_t	siaddr;	/* IP address of next server to use in bootstrap; returned in DHCPOFFER, DHCPACK by server. */
	uint32_t	giaddr;	/* Relay agent IP address, used in booting via a relay agent. */
	uint8_t		chaddr[16];/* Client hardware address. */
	uint8_t		sname[64];/* Optional server host name, null terminated string. */
	uint8_t		file[128];/* Boot file name, null terminated string; "generic" name or null in DHCPDISCOVER, fully qualified directory-path name in DHCPOFFER. */
	uint8_t		options[];/* Optional parameters field. */
} __attribute__((__packed__)) dhcp_hdr_t, *dhcp_hdr_p;

/* Message op code / message type. */
#define DHCP_HDR_OP_BOOTREQUEST	1
#define DHCP_HDR_OP_BOOTREPLY	2
#define DHCP_HDR_OP_MIN		DHCP_HDR_OP_BOOTREQUEST
#define DHCP_HDR_OP_MAX		DHCP_HDR_OP_BOOTREPLY
#define DHCP_HDR_HTYPE_MAX	37
#define DHCP_HDR_HLEN_MAX	16
#define DHCP_HDR_HOPS_MAX	255

#define DHCP_MAGIC_COOKIE	0x63538263 /* (99, 130, 83, 99) - in host byte order. */


static const char *dhcp_header_op[] = {
/*   0 */	NULL,
/*   1 */	"BOOTREQUEST",
/*   2 */	"BOOTREPLY",
};


static const char *dhcp_header_htype[] = {
/*   0 */	"Reserved",
/*   1 */	"Ethernet (10Mb)",
/*   2 */	"Experimental Ethernet (3Mb)",
/*   3 */	"Amateur Radio AX.25",
/*   4 */	"Proteon ProNET Token Ring",
/*   5 */	"Chaos",
/*   6 */	"IEEE 802 Networks",
/*   7 */	"ARCNET",
/*   8 */	"Hyperchannel",
/*   9 */	"Lanstar",
/*  10 */	"Autonet Short Address",
/*  11 */	"LocalTalk",
/*  12 */	"LocalNet (IBM PCNet or SYTEK LocalNET)",
/*  13 */	"Ultra link",
/*  14 */	"SMDS",
/*  15 */	"Frame Relay",
/*  16 */	"Asynchronous Transmission Mode (ATM)",
/*  17 */	"HDLC",
/*  18 */	"Fibre Channel",
/*  19 */	"Asynchronous Transmission Mode (ATM)",
/*  20 */	"Serial Line",
/*  21 */	"Asynchronous Transmission Mode (ATM)",
/*  22 */	"MIL-STD-188-220",
/*  23 */	"Metricom",
/*  24 */	"IEEE 1394.1995",
/*  25 */	"MAPOS",
/*  26 */	"Twinaxial",
/*  27 */	"EUI-64",
/*  28 */	"HIPARP",
/*  29 */	"IP and ARP over ISO 7816-3",
/*  30 */	"ARPSec",
/*  31 */	"IPsec tunnel",
/*  32 */	"InfiniBand (TM)",
/*  33 */	"TIA-102 Project 25 Common Air Interface (CAI)",
/*  34 */	"Wiegand Interface",
/*  35 */	"Pure IP",
/*  36 */	"HW_EXP1",
/*  37 */	"HFI",
};



/* DHCP Standard Options. */
/* RFC 2132 */
/* 3. RFC 1497 Vendor Extensions. */
#define DHCP_OPT_PAD			0
#define DHCP_OPT_SUBNET_MASK		1
#define DHCP_OPT_TIME_OFFSET		2  /* Deprecated by RFC 4833 (100, 101). */
#define DHCP_OPT_ROUTER_ADDRESS		3
#define DHCP_OPT_TIME_SERVERS		4
#define DHCP_OPT_IEN116_NAME_SERVERS	5
#define DHCP_OPT_DOMAIN_NAME_SERVERS	6
#define DHCP_OPT_LOG_SERVERS		7
#define DHCP_OPT_COOKIE_SERVERS		8
#define DHCP_OPT_LPR_SERVERS		9
#define DHCP_OPT_IMPRESS_SERVERS	10
#define DHCP_OPT_RLP_SERVERS		11
#define DHCP_OPT_HOST_NAME		12
#define DHCP_OPT_BOOT_FILE_SIZE		13
#define DHCP_OPT_MERIT_DUMP_FILE	14
#define DHCP_OPT_DOMAIN_NAME		15
#define DHCP_OPT_SWAP_SERVER		16
#define DHCP_OPT_ROOT_PATH		17
#define DHCP_OPT_EXTENSIONS_PATH	18
/* 4. IP Layer Parameters per Host. */
#define DHCP_OPT_IP_FORWARD_ENABLE	19
#define DHCP_OPT_NON_LOCAL_SOURCE_ROUTING 20
#define DHCP_OPT_POLICY_FILTER		21
#define DHCP_OPT_MAX_DATAGRAM_REASSEMBLY_SZ 22
#define DHCP_OPT_IP_DEFAULT_TTL		23
#define DHCP_OPT_PMTU_AGING_TIMEOUT	24
#define DHCP_OPT_PMTU_PLATEAU_TABLE	25
/* 5. IP Layer Parameters per Interface. */
#define DHCP_OPT_INTERFACE_MTU		26
#define DHCP_OPT_ALL_SUBNETS_LOCAL	27
#define DHCP_OPT_BROADCAST_ADDRESS	28
#define DHCP_OPT_PERFORM_MASK_DISCOVERY	29
#define DHCP_OPT_PROVIDE_MASK_TO_OTHERS	30
#define DHCP_OPT_PERFORM_ROUTER_DISCOVERY 31
#define DHCP_OPT_ROUTER_SOLICITATION_ADDR 32
#define DHCP_OPT_STATIC_ROUTES		33
/* 6. Link Layer Parameters per Interface. */
#define DHCP_OPT_TRAILER_ENCAPSULATION	34
#define DHCP_OPT_ARP_CACHE_TIMEOUT	35
#define DHCP_OPT_ETHERNET_ENCAPSULATION	36
/* 7. TCP Parameters. */
#define DHCP_OPT_DEFAULT_TCP_TTL	37
#define DHCP_OPT_KEEP_ALIVE_INTERVAL	38
#define DHCP_OPT_KEEP_ALIVE_GARBAGE	39
/* 8. Application and Service Parameters. */
#define DHCP_OPT_NIS_DOMAIN_NAME	40
#define DHCP_OPT_NIS_SERVERS		41
#define DHCP_OPT_NTP_SERVERS		42
/* 8.4. Vendor Specific Information. */
#define DHCP_OPT_VENDOR_SPEC_INFO	43	/* http://msdn.microsoft.com/en-us/library/cc227275%28v=PROT.10%29.aspx */
/* NetBIOS over TCP/IP Name server option. */
#define DHCP_OPT_NETBIOS_NAME_SERVERS	44
#define DHCP_OPT_NETBIOS_DGM_DIST_SERVER 45
#define DHCP_OPT_NETBIOS_NODE_TYPE	46
#define DHCP_OPT_NETBIOS_SCOPE_OPTION	47
/* X Window System Options. */
#define DHCP_OPT_X_WINDOW_FONT_SERVER	48
#define DHCP_OPT_X_WINDOW_DISPLAY_MANAGER 49
/* 9. DHCP Extensions. */
#define DHCP_OPT_REQUESTED_IP_ADDRESS	50
#define DHCP_OPT_IP_ADDRESS_LEASE_TIME	51
#define DHCP_OPT_OVERLOAD		52
/* */
#define DHCP_OPT_MESSAGE_TYPE		53
#define DHCP_OPT_MESSAGE_TYPE_DISCOVER	1	/* RFC 2132 DHCP Options and BOOTP Vendor Extensions */
#define DHCP_OPT_MESSAGE_TYPE_OFFER	2	/* RFC 2132 DHCP Options and BOOTP Vendor Extensions */
#define DHCP_OPT_MESSAGE_TYPE_REQUEST	3	/* RFC 2132 DHCP Options and BOOTP Vendor Extensions */
#define DHCP_OPT_MESSAGE_TYPE_DECLINE	4	/* RFC 2132 DHCP Options and BOOTP Vendor Extensions */
#define DHCP_OPT_MESSAGE_TYPE_ACK	5	/* RFC 2132 DHCP Options and BOOTP Vendor Extensions */
#define DHCP_OPT_MESSAGE_TYPE_NAK	6	/* RFC 2132 DHCP Options and BOOTP Vendor Extensions */
#define DHCP_OPT_MESSAGE_TYPE_RELEASE	7	/* RFC 2132 DHCP Options and BOOTP Vendor Extensions */
#define DHCP_OPT_MESSAGE_TYPE_INFORM	8	/* RFC 2132 DHCP Options and BOOTP Vendor Extensions */
#define DHCP_OPT_MESSAGE_TYPE_FORCE_RENEW 9	/* RFC 3203 DHCP reconfigure extension. */
#define DHCP_OPT_MESSAGE_TYPE_DHCPLEASEQUERY		10	/* RFC 4388 DHCP Leasequery */
#define DHCP_OPT_MESSAGE_TYPE_DHCPLEASEUNASSIGNED	11	/* RFC 4388 DHCP Leasequery */
#define DHCP_OPT_MESSAGE_TYPE_DHCPLEASEUNKNOWN		12	/* RFC 4388 DHCP Leasequery */
#define DHCP_OPT_MESSAGE_TYPE_DHCPLEASEACTIVE		13	/* RFC 4388 DHCP Leasequery */
/* */
#define DHCP_OPT_DHCP_SERVER_IDENTIFIER	54
#define DHCP_OPT_PARAMETER_REQUEST_LIST	55
#define DHCP_OPT_MESSAGE		56
#define DHCP_OPT_DHCP_MAXIMUM_MSG_SIZE	57
#define DHCP_OPT_RENEWAL_TIME		58	/* T1 */
#define DHCP_OPT_REBINDING_TIME		59	/* T2 */
#define DHCP_OPT_VENDOR_CLASS_IDENTIFIER 60
#define DHCP_OPT_DHCP_CLIENT_IDENTIFIER	61	/* upd: RFC 4361 Node-specific Identifiers for DHCPv4. */
#define DHCP_OPT_NETWARE_DOMAIN_NAME	62	/* RFC 2242 NetWare/IP Domain Name and Information. */
#define DHCP_OPT_NETWARE_SUB_OPTIONS	63	/* RFC 2242 NetWare/IP Domain Name and Information. */
#define DHCP_OPT_NIS_CLIENT_DOMAIN_NAME	64
#define DHCP_OPT_NIS_SERVER_ADDRESS	65
#define DHCP_OPT_TFTP_SERVER_NAME	66
#define DHCP_OPT_BOOTFILE_NAME		67
#define DHCP_OPT_HOME_AGENT_ADDRESS	68
#define DHCP_OPT_SMTP_SERVER_ADDRESS	69
#define DHCP_OPT_POP3_SERVER_ADDRESS	70
#define DHCP_OPT_NNTP_SERVER_ADDRESS	71
#define DHCP_OPT_WWW_SERVER_ADDRESS	72
#define DHCP_OPT_FINGER_SERVER_ADDRESS	73
#define DHCP_OPT_IRC_SERVER_ADDRESS	74
#define DHCP_OPT_STREETTALK_SERVER_ADDRESS 75
#define DHCP_OPT_STREETTALK_DIRECTORY_ASSIST_SRV 76
#define DHCP_OPT_USER_CLASS		77	/* RFC 3004 The User Class Option for DHCP. */
#define DHCP_OPT_SLP_DIRECTORY_AGENT	78	/* RFC 2610 DHCP Options for Service Location Protocol. */
#define DHCP_OPT_SLP_SERVICE_SCOPE	79	/* RFC 2610 DHCP Options for Service Location Protocol. */
#define DHCP_OPT_RAPID_COMMIT		80	/* RFC 4039 Rapid Commit Option for DHCPv4. */
#define DHCP_OPT_CLIENT_FQDN		81	/* RFC 4702 The DHCP Client FQDN Option. */
/* */
#define DHCP_OPT_RELAY_AGENT_INFO	82	/* RFC 3046	DHCP Relay Agent Information Option. */
#define DHCP_OPT_RELAY_AGENT_INFO_CIRCUIT_ID		1	/* RFC 3046	DHCP Relay Agent Information Option. */
#define DHCP_OPT_RELAY_AGENT_INFO_REMOTE_ID		2	/* RFC 3046	DHCP Relay Agent Information Option. */
#define DHCP_OPT_RELAY_AGENT_INFO_DOCSIS_DEVICE_CLASS	4	/* RFC 3046	DHCP Relay Agent Information Option. */
#define DHCP_OPT_RELAY_AGENT_INFO_RELAY_LINK_SELECTION	5	/* RFC 3046	DHCP Relay Agent Information Option. */
#define DHCP_OPT_RELAY_AGENT_INFO_SUBSCRIBER_ID		6	/* RFC 3046	DHCP Relay Agent Information Option. */
#define DHCP_OPT_RELAY_AGENT_INFO_RADIUS_ATTRIBUTES	7	/* RFC 3046	DHCP Relay Agent Information Option. */
#define DHCP_OPT_RELAY_AGENT_INFO_AUTHENTICATION_INFO	8	/* */
#define DHCP_OPT_RELAY_AGENT_INFO_VENDOR_SPECIFIC_INFO	9	/* */
#define DHCP_OPT_RELAY_AGENT_INFO_RELAY_AGENT_FLAGS	10	/* */
#define DHCP_OPT_RELAY_AGENT_INFO_SERVER_ID_OVERRIDE	11	/* */ 
/* */
#define DHCP_OPT_ISNS			83	/* RFC 4174 DHCP Option Number for iSNS. */
/* */
#define DHCP_OPT_NDS_SERVERS		85	/* DHCP Options for Novell Directory Services. */
#define DHCP_OPT_NDS_TREE_NAME		86	/* DHCP Options for Novell Directory Services. */
#define DHCP_OPT_NDS_CONTEXT		87	/* DHCP Options for Novell Directory Services. */
#define DHCP_OPT_BCMCS_CTRL_DOMAIN_NAME_LST 88	/* RFC 3679 // RFC 4280 DHCP Options for BMCS. */
#define DHCP_OPT_BCMCS_CTRL_IPV4_ADDRESS 89	/* RFC 3679 // RFC 4280 DHCP Options for BMCS. */
#define DHCP_OPT_AUTHENTICATION		90	/* RFC 3118 Authentication for DHCP Messages. */
#define DHCP_OPT_CLI_LAST_TRANSACTION_TIME 91	/* RFC 3679 // RFC 4388 DHCP Leasequery. */
#define DHCP_OPT_ASSOCIATED_IP		92	/* RFC 3679 // RFC 4388 DHCP Leasequery. */
#define DHCP_OPT_CLIENT_SYSTEM_ARCHITECTURE 93	/* RFC 4578 DHCP PXE Options. */
#define DHCP_OPT_CLIENT_NET_INTERFACE_ID 94	/* RFC 4578 DHCP PXE Options. */
/* */
#define DHCP_OPT_CLIENT_MACHINE_ID	97	/* RFC 4578 DHCP PXE Options. */
#define DHCP_OPT_UAP			98	/* RFC 2485 DHCP Option for The Open Group's User Authentication Protocol. */
#define DHCP_OPT_GEOCONF_CIVIC		99	/* RFC 4776 Option for Civic Addresses Configuration Information. */
#define DHCP_OPT_TZ_POSIX_STRING	100	/* RFC 4833 Timezone Options for DHCP. */
#define DHCP_OPT_TZ_DATABASE_STRING	101	/* RFC 4833 Timezone Options for DHCP. */
/* */
#define DHCP_OPT_AUTO_CONFIGURE		116	/* RFC 2563 DHCP Option to Disable Stateless Auto-Configuration in IPv4 Clients. */
#define DHCP_OPT_NAME_SERVICE_SEARCH	117	/* RFC 2937 The Name Service Search Option for DHCP. */
#define DHCP_OPT_SUBNET_SELECTION	118	/* RFC 3011 The IPv4 Subnet Selection Option for DHCP. */
/* */
#define DHCP_OPT_CLASSLESS_STATIC_ROUTE	121	/* RFC 3442 Classless Static Route Option for DHCPv4. */
#define DHCP_OPT_CABLELABS_CLIENT_CONFIG 122	/* RFC 3495 DHCP Option for CableLabs Clients. */
#define DHCP_OPT_LOCATION_CONFIG_INFO	123	/* RFC 3825 DHCP Option for Coordinate LCI. */
/* */
#define DHCP_OPT_PANA_AUTHENTICATION_AGENT 136	/* RFC 5192 PAA DHCP Options. */
#define DHCP_OPT_LOST_SERVER		137	/* RFC 5223 DHCP-Based LoST Discovery. */
/* */
#define DHCP_OPT_MOS_ADDRESS		139	/* RFC 5678 Mobility Services for DCHP Options. */
#define DHCP_OPT_MOS_DOMAIN_NAME_LIST	140	/* RFC 5678 Mobility Services for DCHP Options. */
/* */
#define DHCP_OPT_TFTP_SERVER_IP_ADDRESSES 150	/* RFC 5859 TFTP Server Address. */
/* */
#define DHCP_OPT_PXELINUX_MAGIC		208	/* RFC 5071 PXELINUX Options. */
#define DHCP_OPT_PXELINUX_CONFIG_FILE	209	/* RFC 5071 PXELINUX Options. */
#define DHCP_OPT_PXELINUX_PATH_PREFIX	210	/* RFC 5071 PXELINUX Options. */
#define DHCP_OPT_PXELINUX_REBOOT_TIME	211	/* RFC 5071 PXELINUX Options. */
/* */
#define DHCP_OPT_END			255




typedef struct struct dhcp_option_data_s {
	uint8_t		code;	/* DHCP_OPT_* (Assigned by IANA.). */
	uint8_t		len;	/* Size (in octets) of OPTION-DATA. */
	uint8_t		data[];	/* Varies per OPTION-CODE. */
} __attribute__((__packed__)) dhcp_opt_data_t, *dhcp_opt_data_p;



typedef struct struct dhcp_option_params_s {
	const char	*DisplayName;
	uint8_t		Lenght;		/* len. */
	uint8_t		Type;		/* data type. */
	uint16_t	Flags;		/* 2 byte - for allign only. */
	//uint16_t	MsgTypes;	/* apply to message types. */
	void		*DataValues;
	size_t		DataValuesCount;
} __attribute__((__packed__)) dhcp_opt_params_t, *dhcp_opt_params_p;

#define DHCP_OPTP_T_NONE	0
#define DHCP_OPTP_T_SUBOPTS	1
#define DHCP_OPTP_T_BOOL	2
#define DHCP_OPTP_T_1BYTE	3
#define DHCP_OPTP_T_2BYTE	4
#define DHCP_OPTP_T_2TIME	5
#define DHCP_OPTP_T_4BYTE	6
#define DHCP_OPTP_T_4TIME	7
#define DHCP_OPTP_T_IPADDR	8
#define DHCP_OPTP_T_IPIPADDR	9
#define DHCP_OPTP_T_STR		10
#define DHCP_OPTP_T_STRUTF8	11
#define DHCP_OPTP_T_STRRR	12	/* DNS string format. */
#define DHCP_OPTP_T_BYTES	13
#define DHCP_OPTP_T_ADV		14	/* Option have specific format. */
#define DHCP_OPTP_T_PAD		254
#define DHCP_OPTP_T_END		255


#define DHCP_OPTP_F_NONE	0
#define DHCP_OPTP_F_NOLEN	1
#define DHCP_OPTP_F_FIXEDLEN	2
#define DHCP_OPTP_F_MINLEN	4
#define DHCP_OPTP_F_ARRAY	8
/* In case (FIXEDLEN + ARRAY), Len = sizeof 1 element. */


#define DHCP_OPTP_MT_NONE	0
#define DHCP_OPTP_MT_NO_REQ_LIST 1	/* Do not include to DHCP_OPT_PARAMETER_REQUEST_LIST (55). */
#define DHCP_OPTP_MT_DISCOVER	(1 << DHCP_OPT_MESSAGE_TYPE_DISCOVER)
#define DHCP_OPTP_MT_OFFER	(1 << DHCP_OPT_MESSAGE_TYPE_OFFER)
#define DHCP_OPTP_MT_REQUEST	(1 << DHCP_OPT_MESSAGE_TYPE_REQUEST)
#define DHCP_OPTP_MT_DECLINE	(1 << DHCP_OPT_MESSAGE_TYPE_DECLINE)
#define DHCP_OPTP_MT_ACK	(1 << DHCP_OPT_MESSAGE_TYPE_ACK)
#define DHCP_OPTP_MT_NAK	(1 << DHCP_OPT_MESSAGE_TYPE_NAK)
#define DHCP_OPTP_MT_RELEASE	(1 << DHCP_OPT_MESSAGE_TYPE_RELEASE)
#define DHCP_OPTP_MT_INFORM	(1 << DHCP_OPT_MESSAGE_TYPE_INFORM)
#define DHCP_OPTP_MT_FORCE_RENEW (1 << DHCP_OPT_MESSAGE_TYPE_FORCE_RENEW)
#define DHCP_OPTP_MT_DHCPLEASEQUERY	(1 << DHCP_OPT_MESSAGE_TYPE_DHCPLEASEQUERY)
#define DHCP_OPTP_MT_DHCPLEASEUNASSIGNED (1 << DHCP_OPT_MESSAGE_TYPE_DHCPLEASEUNASSIGNED)
#define DHCP_OPTP_MT_DHCPLEASEUNKNOWN	(1 << DHCP_OPT_MESSAGE_TYPE_DHCPLEASEUNKNOWN)
#define DHCP_OPTP_MT_DHCPLEASEACTIVE	(1 << DHCP_OPT_MESSAGE_TYPE_DHCPLEASEACTIVE)


#define DHCP_OPT_PARAMS_UNKNOWN	{ "Unknown", 0, DHCP_OPTP_T_BYTES, DHCP_OPTP_F_MINLEN, NULL, 0 }
#define DHCP_OPT_PARAMS_PAD	{ "PAD", 0, DHCP_OPTP_T_PAD, DHCP_OPTP_F_NOLEN, NULL, 0 }
#define DHCP_OPT_PARAMS_END	{ "END", 0, DHCP_OPTP_T_END, DHCP_OPTP_F_NOLEN, NULL, 0 }


static const dhcp_opt_params_t dhcp_opt_params_unknown = DHCP_OPT_PARAMS_UNKNOWN;
static const dhcp_opt_params_t dhcp_opt_params_pad = DHCP_OPT_PARAMS_PAD;
static const dhcp_opt_params_t dhcp_opt_params_end = DHCP_OPT_PARAMS_END;




static const char *dhcp_opt_enabledisable[] = {
/* 0 */		"disabled",
/* 1 */		"enabled"
};



static const char *dhcp_opt36[] = {
/* 0 */		"Ethernet version 2",
/* 1 */		"IEEE 802.3"
};


static const char *dhcp_opt46[] = {
/* 0 */		NULL,
/* 1 */		"B-node",
/* 2 */		"P-node",
/* 3 */		NULL,
/* 4 */		"M-node",
/* 5 */		NULL,
/* 6 */		NULL,
/* 7 */		NULL,
/* 8 */		"H-node"
};


static const char *dhcp_opt52[] = {
/* 0 */		NULL,
/* 1 */		"file field holds options",
/* 2 */		"sname field holds options",
/* 3 */		"file and sname field holds options"
};


static const char *dhcp_opt53[] = {
	NULL,
	"DISCOVER",
	"OFFER",
	"REQUEST",
	"DECLINE",
	"ACK",
	"NAK",
	"RELEASE",
	"INFORM",
	"FORCE RENEW",
	"DHCPLEASEQUERY",
	"DHCPLEASEUNASSIGNED",
	"DHCPLEASEUNKNOWN",
	"DHCPLEASEACTIVE",
};


static const char *dhcp_opt55[256] = {
// start RFC 2132
/*   0 */	"PAD",
/*   1 */	"Subnet mask",
/*   2 */	"Time offset",
/*   3 */	"Routers",
/*   4 */	"Time servers",
/*   5 */	"Name servers",
/*   6 */	"DNS servers",
/*   7 */	"Log servers",
/*   8 */	"Cookie servers",
/*   9 */	"LPR servers",
/*  10 */	"Impress servers",
/*  11 */	"Resource location servers",
/*  12 */	"Host name",
/*  13 */	"Boot file size",
/*  14 */	"Merit dump file",
/*  15 */	"Domain Name",
/*  16 */	"Swap server",
/*  17 */	"Root path",
/*  18 */	"Extensions path",
/*  19 */	"IP forwarding",
/*  20 */	"Non-local source routing",
/*  21 */	"Policy filter (dst net/mask)",
/*  22 */	"Max dgram reassembly size",
/*  23 */	"Default IP TTL",
/*  24 */	"Path MTU aging timeout",
/*  25 */	"Path MTU plateau table",
/*  26 */	"Interface MTU",
/*  27 */	"All subnets local",
/*  28 */	"Broadcast address",
/*  29 */	"Perform mask discovery",
/*  30 */	"Mask supplier",
/*  31 */	"Perform router discovery",
/*  32 */	"Router solicitation",
/*  33 */	"Static route (dst host/router)",
/*  34 */	"Trailer encapsulation",
/*  35 */	"ARP cache timeout",
/*  36 */	"Ethernet encapsulation",
/*  37 */	"TCP default TTL",
/*  38 */	"TCP keepalive interval",
/*  39 */	"TCP keepalive garbage",
/*  40 */	"NIS domain",
/*  41 */	"NIS servers",
/*  42 */	"NTP servers",
/*  43 */	"Vendor specific info",
/*  44 */	"NetBIOS name servers",
/*  45 */	"NetBIOS dgram distrib servers",
/*  46 */	"NetBIOS node type",
/*  47 */	"NetBIOS scope",
/*  48 */	"X Window font servers",
/*  49 */	"X Window display servers",
/*  50 */	"Request IP address",
/*  51 */	"IP address lease time",
/*  52 */	"Option overload",
/*  53 */	"DHCP message type",
/*  54 */	"DHCP Server identifier",
/*  55 */	"Parameter Request List",
/*  56 */	"Message",
/*  57 */	"Maximum DHCP message size",
/*  58 */	"Renew time (T1)",
/*  59 */	"Rebind time (T2)",
/*  60 */	"Vendor class identifier",
/*  61 */	"DHCP Client identifier",
/*  62 */	"Netware/IP domain name",
/*  63 */	"Netware/IP domain info",
/*  64 */	"NIS+ domain",
/*  65 */	"NIS+ servers",
/*  66 */	"TFTP server name",
/*  67 */	"Bootfile name",
/*  68 */	"Mobile IP home agent",
/*  69 */	"SMTP servers",
/*  70 */	"POP3 servers",
/*  71 */	"NNTP servers",
/*  72 */	"WWW servers",
/*  73 */	"Finger servers",
/*  74 */	"IRC servers",
/*  75 */	"StreetTalk servers",
/*  76 */	"StreetTalk dir assist srv",
/*  77 */	"User Class",
/*  78 */	"SLP Directory Agent",
/*  79 */	"SLP Service Scope",
/*  80 */	"Rapid Commit",
/*  81 */	"Client FQDN",
/*  82 */	"Relay Agent Information",
/*  83 */	"iSNS",
/*  84 */	NULL,
/*  85 */	"NDS server",
/*  86 */	"NDS tree name",
/*  87 */	"NDS context",
/*  88 */	"BCMCS ctrl Domain Name List",
/*  89 */	"BCMCS ctrl IPv4 Address",
/*  90 */	"Authentication",
/*  91 */	"Client last transaction time",
/*  92 */	"Associated IP",
/*  93 */	"PXE Cli System Architecture",
/*  94 */	"PXE Cli Network Interface Id",
/*  95 */	"LDAP Servers",
/*  96 */	NULL,
/*  97 */	"PXE Client Machine Id",
/*  98 */	"UAP servers",
/*  99 */	"Civic Location",
/* 100 */	"Timezone IEEE 1003.1 String",
/* 101 */	"Reference to the TZ Database",
/* 102 - 111 */	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
/* 112 */	"Netinfo Address",
/* 113 */	"Netinfo Tag",
/* 114 */	"URL",
/* 115 */	NULL,
/* 116 */	"Auto Configure",
/* 117 */	"Name Service Search",
/* 118 */	"Subnet selection",
/* 119 */	"Domain Search",
/* 120 */	"SIP Servers",
/* 121 */	"Classless Static Route",
/* 122 */	"CableLabs Client Config",
/* 123 */	"Location Configuration Info",
/* 124 */	"V-I-Vendor Class",
/* 125 */	"V-I-Vendor Specific",
/* 126 */	"Extension 126",
/* 127 */	"Extension 127",
/* 128 */	"TFTP Srv IP Addr (Etherboot)",
/* 129 */	"Call Server IP address",
/* 130 */	"Ethernet Interface",
/* 131 */	"Remote Stats Svr IP Address",
/* 132 */	"IEEE 802.1Q L2 Priority",
/* 133 */	"IEEE 802.1P VLAN ID",
/* 134 */	"Diffserv Code Point",
/* 135 */	"HTTP Proxy",
/* 136 */	"PANA Authentication Agent",
/* 137 */	"LoST Server",
/* 138 */	NULL,
/* 139 */	"MoS IPv4 Address",
/* 140 */	"MoS Domain Name List",
/* 141 - 143 */	NULL, NULL, NULL,
/* 144 */	"HP - TFTP file",
/* 145 - 149 */	NULL, NULL, NULL, NULL, NULL,
/* 150 */	"TFTP Server IP Addresses",
/* 151 - 159 */	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
/* 160 */	"Captive-Portal",
/* 161 - 169 */	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
/* 170 - 169 */	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
/* 180 - 189 */	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
/* 190 - 199 */	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
/* 200 - 207 */	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
/* 208 */	"PXELINUX magic",
/* 209 */	"PXELINUX Config File",
/* 210 */	"PXELINUX Path Prefix",
/* 211 */	"PXELINUX Reboot Time",
/* 212 - 219 */	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
/* 220 - 229 */	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
/* 230 - 239 */	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
/* 240 - 248 */	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
/* 249 */	"MSFT - Classless route",
/* 250 */	"MSFT - Encoding Long Options",
/* 251 */	NULL,
/* 252 */	"MSFT - Web Proxy Auto Detect",
/* 253 */	NULL,
/* 254 */	NULL,
/* 255 */	"END"
};



/* http://technet.microsoft.com/en-us/library/cc977371.aspx */
static const char *dhcp_opt43_MSFT_1[] = {
/* 0 */		NULL,
/* 1 */		dhcp_opt_enabledisable[1],/* NetBT remains enabled. */
/* 2 */		dhcp_opt_enabledisable[0] /* Disable NetBIOS over TCP/IP (NetBT) for Windows 2000 DHCP clients. */
};

static const dhcp_opt_params_t dhcp_opt43_MSFT[] = {
/*   0 */	DHCP_OPT_PARAMS_PAD,
/*   1 */	{ "NetBIOS over TCP/IP (NetBT)", 4,	DHCP_OPTP_T_4BYTE,	(DHCP_OPTP_F_FIXEDLEN), dhcp_opt43_MSFT_1, SIZEOF(dhcp_opt43_MSFT_1)},
/*   2 */	{ "Release DHCP Lease on Shutdown", 4,	DHCP_OPTP_T_4BYTE,	(DHCP_OPTP_F_FIXEDLEN),	dhcp_opt_enabledisable, SIZEOF(dhcp_opt_enabledisable)},
/*   3 */	{ "Default Router Metric Base",	4,	DHCP_OPTP_T_4BYTE,	(DHCP_OPTP_F_FIXEDLEN)},
/*   4 */	DHCP_OPT_PARAMS_UNKNOWN,
/*   5 */	DHCP_OPT_PARAMS_UNKNOWN,
/*   6 */	DHCP_OPT_PARAMS_UNKNOWN,
/*   7 */	DHCP_OPT_PARAMS_UNKNOWN,
/*   8 */	DHCP_OPT_PARAMS_UNKNOWN,
/*   9 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  10 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  11 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  12 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  13 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  14 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  15 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  16 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  17 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  18 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  19 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  20 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  21 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  22 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  23 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  24 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  25 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  26 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  27 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  28 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  29 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  30 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  31 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  32 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  33 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  34 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  35 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  36 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  37 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  38 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  39 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  40 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  41 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  42 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  43 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  44 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  45 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  46 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  47 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  48 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  49 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  50 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  51 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  52 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  53 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  54 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  55 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  56 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  57 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  58 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  59 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  60 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  61 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  62 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  63 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  64 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  65 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  66 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  67 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  68 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  69 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  70 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  71 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  72 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  73 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  74 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  75 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  76 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  77 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  78 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  79 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  80 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  81 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  82 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  83 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  84 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  85 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  86 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  87 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  88 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  89 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  90 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  91 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  92 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  93 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  94 */	{ "Rogue Detection Request", 0,	DHCP_OPTP_T_NONE,	(DHCP_OPTP_F_FIXEDLEN)}, /* http://msdn.microsoft.com/en-us/library/ee808389%28v=PROT.10%29.aspx */
/*  95 */	{ "Rogue Detection Reply", 1,	DHCP_OPTP_T_STR,	(DHCP_OPTP_F_MINLEN)}, /* http://msdn.microsoft.com/en-us/library/ee791538%28v=PROT.10%29.aspx */
/*  96 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  97 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  98 */	DHCP_OPT_PARAMS_UNKNOWN,
/*  99 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 100 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 101 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 102 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 103 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 104 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 105 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 106 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 107 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 108 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 109 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 110 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 111 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 112 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 113 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 114 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 115 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 116 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 117 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 118 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 119 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 120 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 121 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 122 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 123 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 124 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 125 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 126 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 127 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 128 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 129 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 130 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 131 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 132 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 133 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 134 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 135 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 136 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 137 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 138 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 139 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 140 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 141 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 142 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 143 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 144 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 145 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 146 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 147 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 148 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 149 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 150 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 151 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 152 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 153 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 154 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 155 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 156 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 157 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 158 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 159 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 160 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 161 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 162 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 163 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 164 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 165 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 166 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 167 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 168 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 169 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 170 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 171 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 172 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 173 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 174 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 175 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 176 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 177 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 178 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 179 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 180 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 181 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 182 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 183 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 184 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 185 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 186 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 187 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 188 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 189 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 190 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 191 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 192 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 193 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 194 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 195 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 196 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 197 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 198 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 199 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 200 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 201 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 202 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 203 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 204 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 205 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 206 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 207 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 208 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 209 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 210 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 211 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 212 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 213 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 214 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 215 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 216 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 217 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 218 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 219 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 220 */	{ "NAP-SoH",		0,	DHCP_OPTP_T_BYTES}, /* http://technet.microsoft.com/en-us/library/cc227332(PROT.10).aspx */
/* 221 */	{ "NAP-Mask",		4,	DHCP_OPTP_T_4BYTE,	(DHCP_OPTP_F_FIXEDLEN)},
/* 222 */	{ "NAP-CoID",		130,	DHCP_OPTP_T_BYTES,	(DHCP_OPTP_F_FIXEDLEN)},
/* 223 */	{ "NAP-IPv6",		1,	DHCP_OPTP_T_BYTES,	(DHCP_OPTP_F_MINLEN)},
};




union DHCP_OPT_CLIENT_FQDN_FLAGS {
	uint8_t		flags;
	struct FQDN_FLAGS {
		uint8_t MBZ:4;	/* MUST BE ZERO (reserved for future use). */
		uint8_t N:1;	//CS // indicates the encoding of the Domain Name field
		uint8_t E:1;	//CS // indicates whether the server SHOULD NOT perform any DNS updates
		uint8_t O:1;	//-S // indicates whether the server has overridden the client's preference for the "S" bit
		uint8_t S:1;	//CS // indicates whether the server SHOULD or SHOULD NOT perform the A RR (FQDN-to-address) DNS updates
	} hf;
};



static const dhcp_opt_params_t dhcp_opt82_1[] = {
/*   0 */	{ "VLAN(xx)/Module(x)/Port(x)",	4,	DHCP_OPTP_T_BYTES,	(DHCP_OPTP_F_FIXEDLEN)}, /* RFC 3046 DHCP Relay Agent Information Option. */
};

static const dhcp_opt_params_t dhcp_opt82_2[] = {
/*   0 */	{ "MAC address",		6,	DHCP_OPTP_T_BYTES,	(DHCP_OPTP_F_FIXEDLEN)}, /* RFC 3046 DHCP Relay Agent Information Option. */
/*   1 */	{ "User-defined string",	1,	DHCP_OPTP_T_BYTES/*DHCP_OPTP_T_STR*/	,	(DHCP_OPTP_F_MINLEN)}, /* RFC 3046 DHCP Relay Agent Information Option. */
};


static const dhcp_opt_params_t dhcp_opt82[] = {
/*   0 */	DHCP_OPT_PARAMS_UNKNOWN,
/*   1 */	{ "Circuit ID",			2,	DHCP_OPTP_T_SUBOPTS,(DHCP_OPTP_F_MINLEN),	(void*)dhcp_opt82_1, SIZEOF(dhcp_opt82_1)}, /* RFC 3046 DHCP Relay Agent Information Option. */
/*   2 */	{ "Remote ID",			2,	DHCP_OPTP_T_SUBOPTS,(DHCP_OPTP_F_MINLEN),	(void*)dhcp_opt82_2, SIZEOF(dhcp_opt82_2)}, /* RFC 3046 DHCP Relay Agent Information Option. */
/*   3 */	DHCP_OPT_PARAMS_UNKNOWN,
/*   4 */	{ "DOCSIS Device Class",	4,	DHCP_OPTP_T_4BYTE,	(DHCP_OPTP_F_FIXEDLEN)}, /* RFC 3256 The DOCSIS Device Class DHCP. */
/*   5 */	{ "Link selection",		4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN)}, /* RFC 3527 Link Selection sub-option. */
/*   6 */	{ "Subscriber-ID",		1,	DHCP_OPTP_T_STR,	(DHCP_OPTP_F_MINLEN)}, /* RFC 3993 Subscriber-ID Suboption. */
/*   7 */	{ "RADIUS Attributes",		2,	DHCP_OPTP_T_ADV,	(DHCP_OPTP_F_MINLEN)}, /* RFC 4014 RADIUS Attributes Suboption. */
/*   8 */	{ "Authentication",		2,	DHCP_OPTP_T_ADV,	(DHCP_OPTP_F_MINLEN)}, /* RFC 4030 Authentication Suboption. */
/*   9 */	{ "Vendor-Specific",		4,	DHCP_OPTP_T_ADV,	(DHCP_OPTP_F_MINLEN)}, /* RFC 4243 Vendor-Specific Relay Suboption. */
/*  10 */	{ "Flags",			4,	DHCP_OPTP_T_4BYTE,	(DHCP_OPTP_F_FIXEDLEN)}, /* RFC 5010 Relay Agent Flags Suboption. */
/*  11 */	{ "Server ID Override",		4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN)}, /* RFC 5107 Server ID Override Suboption, see opt 54 - DHCP Server identifier. */
};




static const dhcp_opt_params_t dhcp_options[256] = {
/* Start RFC 2132. */
/*   0 */	DHCP_OPT_PARAMS_PAD,
/*   1 */	{ dhcp_opt55[1],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN)},
/*   2 */	{ dhcp_opt55[2],	4,	DHCP_OPTP_T_4BYTE,	(DHCP_OPTP_F_FIXEDLEN)}, /* Deprecated by RFC 4833 (100, 101). */
/*   3 */	{ dhcp_opt55[3],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)},
/*   4 */	{ dhcp_opt55[4],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)},
/*   5 */	{ dhcp_opt55[5],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)},
/*   6 */	{ dhcp_opt55[6],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)},
/*   7 */	{ dhcp_opt55[7],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)},
/*   8 */	{ dhcp_opt55[8],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)},
/*   9 */	{ dhcp_opt55[9],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)},
/*  10 */	{ dhcp_opt55[10],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)},
/*  11 */	{ dhcp_opt55[11],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)},
/*  12 */	{ dhcp_opt55[12],	1,	DHCP_OPTP_T_STR,	(DHCP_OPTP_F_MINLEN)},
/*  13 */	{ dhcp_opt55[13],	2,	DHCP_OPTP_T_2BYTE,	(DHCP_OPTP_F_FIXEDLEN)},
/*  14 */	{ dhcp_opt55[14],	1,	DHCP_OPTP_T_STR,	(DHCP_OPTP_F_MINLEN)},
/*  15 */	{ dhcp_opt55[15],	1,	DHCP_OPTP_T_STR,	(DHCP_OPTP_F_MINLEN)},
/*  16 */	{ dhcp_opt55[16],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN)},
/*  17 */	{ dhcp_opt55[17],	1,	DHCP_OPTP_T_STR,	(DHCP_OPTP_F_MINLEN)},
/*  18 */	{ dhcp_opt55[18],	1,	DHCP_OPTP_T_ADV,	(DHCP_OPTP_F_MINLEN)},
/*  19 */	{ dhcp_opt55[19],	1,	DHCP_OPTP_T_BOOL,	(DHCP_OPTP_F_FIXEDLEN)},
/*  20 */	{ dhcp_opt55[20],	1,	DHCP_OPTP_T_BOOL,	(DHCP_OPTP_F_FIXEDLEN)},
/*  21 */	{ dhcp_opt55[21],	8,	DHCP_OPTP_T_IPIPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)},
/*  22 */	{ dhcp_opt55[22],	2,	DHCP_OPTP_T_2BYTE,	(DHCP_OPTP_F_FIXEDLEN)},
/*  23 */	{ dhcp_opt55[23],	1,	DHCP_OPTP_T_1BYTE,	(DHCP_OPTP_F_FIXEDLEN)},
/*  24 */	{ dhcp_opt55[24],	4,	DHCP_OPTP_T_4BYTE,	(DHCP_OPTP_F_FIXEDLEN)},
/*  25 */	{ dhcp_opt55[25],	2,	DHCP_OPTP_T_2BYTE,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)},
/*  26 */	{ dhcp_opt55[26],	2,	DHCP_OPTP_T_2BYTE,	(DHCP_OPTP_F_FIXEDLEN)},
/*  27 */	{ dhcp_opt55[27],	1,	DHCP_OPTP_T_BOOL,	(DHCP_OPTP_F_FIXEDLEN)},
/*  28 */	{ dhcp_opt55[28],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN)},
/*  29 */	{ dhcp_opt55[29],	1,	DHCP_OPTP_T_BOOL,	(DHCP_OPTP_F_FIXEDLEN)},
/*  30 */	{ dhcp_opt55[30],	1,	DHCP_OPTP_T_BOOL,	(DHCP_OPTP_F_FIXEDLEN)},
/*  31 */	{ dhcp_opt55[31],	1,	DHCP_OPTP_T_BOOL,	(DHCP_OPTP_F_FIXEDLEN)},
/*  32 */	{ dhcp_opt55[32],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN)},
/*  33 */	{ dhcp_opt55[33],	8,	DHCP_OPTP_T_IPIPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)},
/*  34 */	{ dhcp_opt55[34],	1,	DHCP_OPTP_T_BOOL,	(DHCP_OPTP_F_FIXEDLEN)},
/*  35 */	{ dhcp_opt55[35],	4,	DHCP_OPTP_T_4BYTE,	(DHCP_OPTP_F_FIXEDLEN)},
/*  36 */	{ dhcp_opt55[36],	1,	DHCP_OPTP_T_BOOL,	(DHCP_OPTP_F_FIXEDLEN),					dhcp_opt36, SIZEOF(dhcp_opt36)},
/*  37 */	{ dhcp_opt55[37],	1,	DHCP_OPTP_T_1BYTE,	(DHCP_OPTP_F_FIXEDLEN)},
/*  38 */	{ dhcp_opt55[38],	4,	DHCP_OPTP_T_4TIME,	(DHCP_OPTP_F_FIXEDLEN)},
/*  39 */	{ dhcp_opt55[39],	1,	DHCP_OPTP_T_BOOL,	(DHCP_OPTP_F_FIXEDLEN)},
/*  40 */	{ dhcp_opt55[40],	1,	DHCP_OPTP_T_STR,	(DHCP_OPTP_F_MINLEN)},
/*  41 */	{ dhcp_opt55[41],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)},
/*  42 */	{ dhcp_opt55[42],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)},
/*  43 */	{ dhcp_opt55[43],	1,	DHCP_OPTP_T_SUBOPTS,	(DHCP_OPTP_F_MINLEN),					(void*)dhcp_opt43_MSFT, SIZEOF(dhcp_opt43_MSFT)}, /* http://msdn.microsoft.com/en-us/library/cc227275%28v=PROT.10%29.aspx */
/*  44 */	{ dhcp_opt55[44],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)},
/*  45 */	{ dhcp_opt55[45],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)},
/*  46 */	{ dhcp_opt55[46],	1,	DHCP_OPTP_T_1BYTE,	(DHCP_OPTP_F_FIXEDLEN),					dhcp_opt46, SIZEOF(dhcp_opt46)},
/*  47 */	{ dhcp_opt55[47],	1,	DHCP_OPTP_T_BYTES,	(DHCP_OPTP_F_MINLEN)},
/*  48 */	{ dhcp_opt55[48],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)},
/*  49 */	{ dhcp_opt55[49],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)},
/*  50 */	{ dhcp_opt55[50],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN)},
/*  51 */	{ dhcp_opt55[51],	4,	DHCP_OPTP_T_4TIME,	(DHCP_OPTP_F_FIXEDLEN)},
/*  52 */	{ dhcp_opt55[52],	1,	DHCP_OPTP_T_1BYTE,	(DHCP_OPTP_F_FIXEDLEN),					dhcp_opt52, SIZEOF(dhcp_opt52)},
/*  53 */	{ dhcp_opt55[53],	1,	DHCP_OPTP_T_1BYTE,	(DHCP_OPTP_F_FIXEDLEN),					dhcp_opt53, SIZEOF(dhcp_opt53)},
/*  54 */	{ dhcp_opt55[54],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN)},
/*  55 */	{ dhcp_opt55[55],	1,	DHCP_OPTP_T_1BYTE,	(DHCP_OPTP_F_MINLEN|DHCP_OPTP_F_ARRAY),	dhcp_opt55, SIZEOF(dhcp_opt55)},
/*  56 */	{ dhcp_opt55[56],	1,	DHCP_OPTP_T_STR,	(DHCP_OPTP_F_MINLEN)},
/*  57 */	{ dhcp_opt55[57],	2,	DHCP_OPTP_T_2BYTE,	(DHCP_OPTP_F_FIXEDLEN)},
/*  58 */	{ dhcp_opt55[58],	4,	DHCP_OPTP_T_4TIME,	(DHCP_OPTP_F_FIXEDLEN)},
/*  59 */	{ dhcp_opt55[59],	4,	DHCP_OPTP_T_4TIME,	(DHCP_OPTP_F_FIXEDLEN)},
/*  60 */	{ dhcp_opt55[60],	1,	DHCP_OPTP_T_STR,	(DHCP_OPTP_F_MINLEN)},
/*  61 */	{ dhcp_opt55[61],	2,	DHCP_OPTP_T_ADV,	(DHCP_OPTP_F_MINLEN)}, /* upd: RFC 4361. */
/*  62 */	{ dhcp_opt55[62],	1,	DHCP_OPTP_T_STR,	(DHCP_OPTP_F_MINLEN)}, /* RFC 2242. */
/*  63 */	{ dhcp_opt55[63],	2,	DHCP_OPTP_T_ADV,	(DHCP_OPTP_F_MINLEN)}, /* RFC 2242. */
/*  64 */	{ dhcp_opt55[64],	1,	DHCP_OPTP_T_STR,	(DHCP_OPTP_F_MINLEN)},
/*  65 */	{ dhcp_opt55[65],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)},
/*  66 */	{ dhcp_opt55[66],	1,	DHCP_OPTP_T_STR,	(DHCP_OPTP_F_MINLEN)},
/*  67 */	{ dhcp_opt55[67],	1,	DHCP_OPTP_T_STR,	(DHCP_OPTP_F_MINLEN)},
/*  68 */	{ dhcp_opt55[68],	0,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)},
/*  69 */	{ dhcp_opt55[69],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)},
/*  70 */	{ dhcp_opt55[70],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)},
/*  71 */	{ dhcp_opt55[71],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)},
/*  72 */	{ dhcp_opt55[72],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)},
/*  73 */	{ dhcp_opt55[73],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)},
/*  74 */	{ dhcp_opt55[74],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)},
/*  75 */	{ dhcp_opt55[75],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)},
/*  76 */	{ dhcp_opt55[76],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)},
/* End RFC 2132. */
/*  77 */	{ dhcp_opt55[77],	2,	DHCP_OPTP_T_ADV,	(DHCP_OPTP_F_MINLEN)}, /* RFC 3004 The User Class Option for DHCP. */
/*  78 */	{ dhcp_opt55[78],	5,	DHCP_OPTP_T_ADV,	(DHCP_OPTP_F_MINLEN)}, /* RFC 2610 DHCP Options for Service Location Protocol. */
/*  79 */	{ dhcp_opt55[79],	2,	DHCP_OPTP_T_ADV,	(DHCP_OPTP_F_MINLEN)}, /* RFC 2610 DHCP Options for Service Location Protocol. */
/*  80 */	{ dhcp_opt55[80],	0,	DHCP_OPTP_T_NONE,	(DHCP_OPTP_F_FIXEDLEN)}, /* RFC 3679 // RFC 4039 Rapid Commit Option for DHCPv4. */
/*  81 */	{ dhcp_opt55[81],	3,	DHCP_OPTP_T_ADV,	(DHCP_OPTP_F_MINLEN)}, /* RFC 4702 The DHCP Client FQDN Option. */
/*  82 */	{ dhcp_opt55[82],	2,	DHCP_OPTP_T_SUBOPTS,	(DHCP_OPTP_F_MINLEN),					(void*)dhcp_opt82, SIZEOF(dhcp_opt82)}, /* RFC 3046 DHCP Relay Agent Information Option. */
/*  83 */	{ dhcp_opt55[83],	18,	DHCP_OPTP_T_ADV,	(DHCP_OPTP_F_MINLEN)}, /* RFC 3679 // RFC 4174 DHCP Option Number for iSNS. */
/*  84 */	DHCP_OPT_PARAMS_UNKNOWN, /* RFC 3679. */
/*  85 */	{ dhcp_opt55[85],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)}, /* RFC 2241 DHCP Options for Novell Directory Services. */
/*  86 */	{ dhcp_opt55[86],	2,	DHCP_OPTP_T_STRUTF8,	(DHCP_OPTP_F_MINLEN)}, /* RFC 2241 DHCP Options for Novell Directory Services. */
/*  87 */	{ dhcp_opt55[87],	2,	DHCP_OPTP_T_STRUTF8,	(DHCP_OPTP_F_MINLEN)}, /* RFC 2241 DHCP Options for Novell Directory Services. */
/*  88 */	{ dhcp_opt55[88],	0,	DHCP_OPTP_T_STRRR,	(DHCP_OPTP_F_ARRAY)}, /* RFC 3679 // RFC 4280 DHCP Options for BMCS. */
/*  89 */	{ dhcp_opt55[89],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)}, /* RFC 3679 // RFC 4280 DHCP Options for BMCS. */
/*  90 */	{ dhcp_opt55[90],	8,	DHCP_OPTP_T_ADV,	(DHCP_OPTP_F_MINLEN)}, /* RFC 3118. */
/*  91 */	{ dhcp_opt55[91],	4,	DHCP_OPTP_T_4TIME,	(DHCP_OPTP_F_FIXEDLEN)}, /* RFC 3679 // RFC 4388 DHCP Leasequery. */
/*  92 */	{ dhcp_opt55[92],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)}, /* RFC 3679 // RFC 4388 DHCP Leasequery. */
/*  93 */	{ dhcp_opt55[93],	2,	DHCP_OPTP_T_2BYTE,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)}, /* RFC 3679 // RFC 4578 DHCP PXE Options. */
/*  94 */	{ dhcp_opt55[94],	3,	DHCP_OPTP_T_ADV,	(DHCP_OPTP_F_FIXEDLEN)}, /* RFC 3679 // RFC 4578 DHCP PXE Options. */
/*  95 */	{ dhcp_opt55[95],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)}, /* RFC 3679. */
/*  96 */	DHCP_OPT_PARAMS_UNKNOWN, /* RFC 3679. */
/*  97 */	{ dhcp_opt55[97],	1,	DHCP_OPTP_T_ADV,	(DHCP_OPTP_F_MINLEN)}, /* RFC 3679 // RFC 4578 DHCP PXE Options. */
/*  98 */	{ dhcp_opt55[98],	4,	DHCP_OPTP_T_STR,	(DHCP_OPTP_F_MINLEN)}, /* RFC 2485 DHCP Option for The Open Group's User Authentication Protocol. */
/*  99 */	{ dhcp_opt55[99],	3,	DHCP_OPTP_T_ADV,	(DHCP_OPTP_F_MINLEN)}, /* RFC 4776 Option for Civic Addresses Configuration Information. */
/* 100 */	{ dhcp_opt55[100],	1,	DHCP_OPTP_T_STR,	(DHCP_OPTP_F_MINLEN)}, /* RFC 3679 // RFC 4833 Timezone Options for DHCP. */
/* 101 */	{ dhcp_opt55[101],	1,	DHCP_OPTP_T_STR,	(DHCP_OPTP_F_MINLEN)}, /* RFC 3679 // RFC 4833 Timezone Options for DHCP. */
/* 102 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 103 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 104 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 105 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 106 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 107 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 108 */	DHCP_OPT_PARAMS_UNKNOWN, /* RFC 3679. */
/* 109 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 110 */	DHCP_OPT_PARAMS_UNKNOWN, /* RFC 3679. */
/* 111 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 112 */	{ dhcp_opt55[112],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)},
/* 113 */	{ dhcp_opt55[113],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)},
/* 114 */	{ dhcp_opt55[114],	1,	DHCP_OPTP_T_STR,	(DHCP_OPTP_F_MINLEN)}, /* RFC 3679. */
/* 115 */	DHCP_OPT_PARAMS_UNKNOWN, /* RFC 3679. */
/* 116 */	{ dhcp_opt55[116],	1,	DHCP_OPTP_T_BOOL,	(DHCP_OPTP_F_FIXEDLEN)}, /* RFC 2563 DHCP Option to Disable Stateless Auto-Configuration in IPv4 Clients. */
/* 117 */	{ dhcp_opt55[117],	2,	DHCP_OPTP_T_2BYTE,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)}, /* RFC 2937 The Name Service Search Option for DHCP. */
/* 118 */	{ dhcp_opt55[118],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN)}, /* RFC 3011 The IPv4 Subnet Selection Option for DHCP. */
/* 119 */	{ dhcp_opt55[119],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)},
/* 120 */	{ dhcp_opt55[120],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)},
/* 121 */	{ dhcp_opt55[121],	5,	DHCP_OPTP_T_ADV,	(DHCP_OPTP_F_MINLEN)}, /* RFC 3442 Classless Static Route Option for DHCPv4. */
/* 122 */	{ dhcp_opt55[122],	2,	DHCP_OPTP_T_ADV,	(DHCP_OPTP_F_MINLEN)}, /* RFC 3495 DHCP Option for CableLabs Clients. */
/* 123 */	{ dhcp_opt55[123],	16,	DHCP_OPTP_T_ADV,	(DHCP_OPTP_F_FIXEDLEN)}, /* RFC 3825 DHCP Option for Coordinate LCI. */
/* 124 */	{ dhcp_opt55[124],	0,	DHCP_OPTP_T_NONE,	(DHCP_OPTP_F_NONE)},// UNDONE!!!!
/* 125 */	{ dhcp_opt55[125],	0,	DHCP_OPTP_T_NONE,	(DHCP_OPTP_F_NONE)},// UNDONE!!!!
/* 126 */	{ dhcp_opt55[126],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)},
/* 127 */	{ dhcp_opt55[127],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)},
/* 128 */	{ dhcp_opt55[128],	0,	DHCP_OPTP_T_NONE,	(DHCP_OPTP_F_NONE)},// UNDONE!!!!
/* 129 */	{ dhcp_opt55[129],	0,	DHCP_OPTP_T_NONE,	(DHCP_OPTP_F_NONE)},// UNDONE!!!!
/* 130 */	{ dhcp_opt55[130],	0,	DHCP_OPTP_T_NONE,	(DHCP_OPTP_F_NONE)},// UNDONE!!!!
/* 131 */	{ dhcp_opt55[131],	0,	DHCP_OPTP_T_NONE,	(DHCP_OPTP_F_NONE)},// UNDONE!!!!
/* 132 */	{ dhcp_opt55[132],	0,	DHCP_OPTP_T_NONE,	(DHCP_OPTP_F_NONE)},// UNDONE!!!!
/* 133 */	{ dhcp_opt55[133],	0,	DHCP_OPTP_T_NONE,	(DHCP_OPTP_F_NONE)},// UNDONE!!!!
/* 134 */	{ dhcp_opt55[134],	0,	DHCP_OPTP_T_NONE,	(DHCP_OPTP_F_NONE)},// UNDONE!!!!
/* 135 */	{ dhcp_opt55[135],	0,	DHCP_OPTP_T_NONE,	(DHCP_OPTP_F_NONE)},// UNDONE!!!!
/* 136 */	{ dhcp_opt55[136],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)}, /* RFC 5192 PAA DHCP Options. */
/* 137 */	{ dhcp_opt55[137],	1,	DHCP_OPTP_T_ADV,	(DHCP_OPTP_F_MINLEN)}, /* RFC 5223 DHCP-Based LoST Discovery. */
/* 138 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 139 */	{ dhcp_opt55[139],	2,	DHCP_OPTP_T_ADV,	(DHCP_OPTP_F_MINLEN)}, /* RFC 5678 Mobility Services for DCHP Options. */
/* 140 */	{ dhcp_opt55[140],	2,	DHCP_OPTP_T_ADV,	(DHCP_OPTP_F_MINLEN)}, /* RFC 5678 Mobility Services for DCHP Options. */
/* 141 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 142 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 143 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 144 */	{ dhcp_opt55[144],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)},
/* 145 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 146 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 147 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 148 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 149 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 150 */	{ dhcp_opt55[150],	4,	DHCP_OPTP_T_IPADDR,	(DHCP_OPTP_F_FIXEDLEN|DHCP_OPTP_F_ARRAY)}, /* RFC 5859 TFTP Server Address. */
/* 151 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 152 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 153 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 154 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 155 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 156 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 157 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 158 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 159 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 160 */	{ dhcp_opt55[160],	1,	DHCP_OPTP_T_STR,	(DHCP_OPTP_F_MINLEN)}, /* RFC 7710. */
/* 161 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 162 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 163 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 164 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 165 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 166 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 167 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 168 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 169 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 170 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 171 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 172 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 173 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 174 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 175 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 176 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 177 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 178 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 179 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 180 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 181 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 182 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 183 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 184 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 185 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 186 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 187 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 188 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 189 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 190 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 191 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 192 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 193 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 194 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 195 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 196 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 197 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 198 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 199 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 200 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 201 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 202 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 203 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 204 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 205 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 206 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 207 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 208 */	{ dhcp_opt55[208],	4,	DHCP_OPTP_T_4BYTE,	(DHCP_OPTP_F_FIXEDLEN)}, /* RFC 5071 PXELINUX Options. */
/* 209 */	{ dhcp_opt55[209],	1,	DHCP_OPTP_T_STR,	(DHCP_OPTP_F_MINLEN)}, /* RFC 5071 PXELINUX Options. */
/* 210 */	{ dhcp_opt55[210],	1,	DHCP_OPTP_T_STR,	(DHCP_OPTP_F_MINLEN)}, /* RFC 5071 PXELINUX Options. */
/* 211 */	{ dhcp_opt55[211],	4,	DHCP_OPTP_T_4TIME,	(DHCP_OPTP_F_FIXEDLEN)}, /* RFC 5071 PXELINUX Options. */
/* 212 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 213 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 214 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 215 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 216 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 217 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 218 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 219 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 220 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 221 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 222 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 223 */	DHCP_OPT_PARAMS_UNKNOWN,
/* Site-specific options. */
/* 224 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 225 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 226 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 227 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 228 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 229 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 230 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 231 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 232 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 233 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 234 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 235 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 236 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 237 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 238 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 239 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 240 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 241 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 242 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 243 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 244 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 245 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 246 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 247 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 248 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 249 */	{ dhcp_opt55[249],	5,	DHCP_OPTP_T_ADV,	(DHCP_OPTP_F_MINLEN)}, /* MSFT - Classless routes. */
/* 250 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 251 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 252 */	{ dhcp_opt55[252],	1,	DHCP_OPTP_T_STR,	(DHCP_OPTP_F_MINLEN)},
/* 253 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 254 */	DHCP_OPT_PARAMS_UNKNOWN,
/* 255 */	DHCP_OPT_PARAMS_END /* RFC 2132. */
};


//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

//
//  Inline byte flipping -- can be done in registers
//

#ifndef NTOHS

static inline uint16_t
USHORT_FLIP(uint16_t usIn) {

	return (((usIn << 8) | (usIn >> 8)));
}
#define NTOHS(in)   USHORT_FLIP(in)
#define HTONS(in)   USHORT_FLIP(in)

#endif



#ifndef NTOHL

static inline uint32_t
ULONG_FLIP(uint32_t ulIn) {
#if defined (_M_IA64) || defined (_M_AMD64)
	return ((((ulIn << 8) & 0x00ff0000) | (ulIn << 24) | ((ulIn >> 8) & 0x0000ff00) | (ulIn >> 24)));
#else
	__asm {
		mov	eax, ulIn
		bswap	eax
		mov	ulIn, eax
	};
	return (ulIn);
#endif
}

#define NTOHL(in) ULONG_FLIP(in)
#define HTONL(in) ULONG_FLIP(in)

#endif




static inline void
DHCPHeaderFlip(dhcp_hdr_p hdr) {
	// op
	// htype
	// hlen
	// hops
	hdr->xid = ULONG_FLIP(hdr->xid);
	hdr->secs = USHORT_FLIP(hdr->secs);
	// flags
	//hdr->ciaddr = ULONG_FLIP(hdr->ciaddr);
	//hdr->yiaddr = ULONG_FLIP(hdr->yiaddr);
	//hdr->siaddr = ULONG_FLIP(hdr->siaddr);
	//hdr->giaddr = ULONG_FLIP(hdr->giaddr);
	// chaddr[16]
	// sname[64]
	// file[128]
	// options[]
}



static inline uint32_t
DHCPHeaderValidate(dhcp_hdr_p hdr, size_t pkt_size) {
	uint32_t ret = 0;

	if (dwDHCPPacketSize < (sizeof(dhcp_hdr_t) + 4))
		return (255); // cant check other

	///////////////if (pkt_size < DHCP_MIN_PACKET_LENGTH) ret ++;
	if (DHCP_HDR_OP_MIN > hdr->op ||
	    DHCP_HDR_OP_MAX < hdr->op)
		ret ++;
	if (hdr->htype > DHCP_HDR_HTYPE_MAX)
		ret ++;
	if (hdr->hlen > DHCP_HDR_HLEN_MAX)
		ret ++;
	if (hdr->hops > DHCP_HDR_HOPS_MAX)
		ret ++;
	///////////////if (hdr->flags.hf.MBZ != 0) ret ++;

	if ((*((uint32_t*)(hdr + 1))) != DHCP_MAGIC_COOKIE)
		ret ++;

	return (ret);
}





#endif /* __DHCP_MESSAGE_H__ */
