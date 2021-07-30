#ifndef IKE_H
#define IKE_H

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <getopt.h>
#include <rte_byteorder.h>
#include <rte_mbuf.h>
#include <string.h>
#include "array.h"
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_esp.h>
#include <rte_udp.h>
#include <stdbool.h>
#include "log.h"
#include "../deps/b64/b64.h"

int src_addr_int;
int dst_addr_int;
char src_addr[128];
char dst_addr[128];
char current_time[24];
static const int ESP_OFFSET = sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_ether_hdr) + sizeof(struct rte_udp_hdr);
static const int ISAKMP_OFFSET = sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_ether_hdr) + sizeof(struct rte_udp_hdr) + 4;
static const int first_payload_hdr_offset = ESP_OFFSET + 28;

static const int ESP_OFFSET_6 = sizeof(struct rte_ipv6_hdr) + sizeof(struct rte_ether_hdr) + sizeof(struct rte_udp_hdr);
static const int ISAKMP_OFFSET_6 = sizeof(struct rte_ipv6_hdr) + sizeof(struct rte_ether_hdr) + sizeof(struct rte_udp_hdr) + 4;
static const int first_payload_hdr_offset_6 = ESP_OFFSET_6 + 28;

static const int serialize_size = 32;
struct Array *tunnels;

static const char * transform_types[5] = { "Encryption Algorithm","Pseudorandom Function","Integrity Algorithm","Diffie-Hellman Group","Extended Sequence Numbers"};

static const char * exchange_types[4] = {"IKE_SA_INIT","IKE_AUTH","CREATE_CHILD_SA","INFORMATIONAL"};

static const char * payload_types[17] = {"Security Association", "Key Exchange", "Identification - Initiator", 
"Identification - Responder", "Certificate", "Certificate Request", "Authentication", "Nonce",
"Notify", "Delete", "Vendor ID", "Traffic Selector - Initiator", "Traffic Selector - Responder",
"Encrypted and Authenticated", "Configuration", "Extensible Authentication"};

static const char* notify_msg_type[44] = {"UNSUPPORTED_CRIT_PAYLOAD\n","\0","\0","INVALID_IKE_SPI\n",
"INVALID_MAJOR_VERSION\n","\0","INVALID_SYNTAX\n","\0","INVALID_MSG_ID\n","\0","INVALID_SPI\n","\0","\0","NO_PROPOSAL_CHOSEN\n",
"\0","\0","INVALID_KE_PAYLOAD\n","\0","\0","\0","\0","\0","\0","AUTH_FAILED\n","\0","\0","\0","\0","\0","\0","\0","\0","\0",
"SINGLE_PAIR_REQUIRED\n","NO_ADDITIONAL_SAS\n","INTERNAL_ADDRESS_FAILURE\n","FAILED_CP_REQUIRED\n","TS_UNACCEPTABLE\n",
"INVALID_SELECTORS\n","\0","\0","\0","TEMPORARY_FAILURE\n","CHILD_SA_NOT_FOUND\n"};

static const char* cert_encoding[13] = {"PKCS #7 wrapped X.509 certificate ","PGP Certificate","DNS Signed Key","X.509 Certificate - Signature","\0","Kerberos Token",
"Certificate Revocation List (CRL)","Authority Revocation List (ARL)","SPKI Certificate","X.509 Certificate - Attribute","Raw RSA Key","Hash and URL of X.509 certificate",
"Hash and URL of X.509 bundle"};

static const char* encr_algo[35] = {"DES_IV64","DES","3DES","RCS","IDEA","CAST","BLOWFISH","3IDEA","DES_IV32","\0","NONE","AES_CBC","AES_CTR","AES_CCM_8","AES_CCM_12",
"AES_CCM_16","\0","AES_GCM_8","AES_GCM_12","AES_GCM_16","NULL_AUTH_AWS_GMAC","AES_XTS","CAMELLIA_CBC","CAMELLIA_CTR","CAMELLIA_CCM_8","CAMELLIA_CCM_12","CAMELLIA_CCM_16",
"CHACHA20_POLY_1305","AES_CCM_8_IIV","AES_GCM_16_IIV","CHACHA20_POLY1305_IIV","KUZNYECHIK_MGM_KTREE","MAGMA_MGM_KTREE","KUZNYECHIK_MGM_MAC_KTREE","MAGMA_MGM_MAC_KTREE"};

static const char* pseudorandom_func[9] = {"HMAC_MD5","HMAC_SHA1","HMAC_TIGER","AES128_XCBC","HMAC_SHA2_256","HMAC_SHA2_384","HMAC_SHA2_512","AES128_CMAC","HMAC_STRIBOG_512"};

static const char* integrity_func[15] = {"INTEG_NONE","HMAC_MD5_96","HMAC_SHA1_96","DES_MAC","KPDK_MD5","AES_XCBC_96","HMAC_MD5_128","HMAC_SHA1_160","AES_CMAC_96",
"AES_128_GMAC","AES_192_GMAC","AES_256_GMAC","HMAC_SHA2_256_128","HMAC_SHA2_384_192","HMAC_SHA2_512_256"};

static const char* DH[27] = {"DH_NONE","MODP_768","MODP_1024","\0","\0","MODP_1536","\0","\0","\0","\0","\0","\0","\0","\0","MODP_2048","MODP_3072","MODP_4096",
"MODP_6144","MODP_8192","ECP_256","ECP_384","ECP_521","MODP_1024_PO_160","MODP_2048_PO_224","MODP_2048_PO_256","ECP_192","ECP_224"};

///Exchange Type of IKE packet
enum EXCHANGE_TYPE{
    IKE_SA_INIT = 34,
    IKE_AUTH = 35,
    CREATE_CHILD_SA = 36,
    INFORMATIONAL = 37
};

///Payload of IKE packet
enum NEXT_PAYLOAD{
    NO = 0,
    SA = 33,
    KE = 34,
    IDI = 35, 
    IDR = 36,
    CERT = 37,
    CERTREQ = 38,
    AUTH = 39,
    NONCE = 40,
    N = 41,
    D = 42,
    V = 43,
    TSI = 44,
    TSR = 45,
    SK = 46,
    CP = 47,
    EAP = 48,
    SKF = 53 
};

enum protocol{
    IKE = 1,
    AH = 2,
    ESP = 3
};

//Transform Type used for proposals
enum TRANSFORM_TYPE{
    /** Encryption Algorithm */
    ENCR = 1, 
    /** Pseudorandom function */
    PRF = 2,
    /** Integrity Algorithm */
    INTEG = 3, 
    /**  Diffie-Hellman Group */
    D_H = 4,
    /** Extended Sequence Numbers */
    ESN = 5 
};

/// Encryption Algorithms
enum ENCR{
    DES_IV64 = 1,
    DES = 2,
    _3DES = 3,
    RC5 = 4,
    IDEA = 5,
    CAST = 6,
    BLOWFISH = 7,
    _3IDEA = 8,
    DES_IV32 = 9,
    NONE = 11,
    AES_CBC = 12,
    AES_CTR = 13,
    AES_CCM_8 = 14,
    AES_CCM_12 = 15,
    AES_CCM_16 = 16,
    AES_GCM_8 = 18,
    AES_GCM_12 = 19,
    AES_GCM_16 = 20,
    NULL_AUTH_AES_GMAC = 21,
    XTS_AES = 22,
    CAMELLIA_CBC = 23,
    CAMELLIA_CTR = 24,
    CAMELLIA_CCM_8 = 25,
    CAMELLIA_CCM_12 = 26,
    CAMELLIA_CCM_16 = 27,
    CHACHA20_POLY1305 = 28,
    AES_CCM_8_IIV = 29,
    AES_GCM_16_IIV = 30,
    CHACHA20_POLY1305_IIV = 31,
    KUZNYECHIK_MGM_KTREE = 32,
    MAGMA_MGM_KTREE = 33,
    KUZNYECHIK_MGM_MAC_KTREE = 34,
    MAGMA_MGM_MAC_KTREE = 35
};

/// Pseudorandom function
enum PRF{
    HMAC_MD5 = 1,
    HMAC_SHA1 = 2,
    HMAC_TIGER = 3,
    AES128_XCBC = 4,
    HMAC_SHA2_256 = 5,
    HMAC_SHA2_384 = 6,
    HMAC_SHA2_512 = 7,
    AES128_CMAC = 8,
    HMAC_STRIBOG_512 = 9
};

/// Integrity Algorithm
enum INTEG{
    INTEG_NONE = 0,
    HMAC_MD5_96 = 1,
    HMAC_SHA1_96 = 2,
    DES_MAC = 3,
    KPDK_MD5 = 4,
    AES_XCBC_96 = 5,
    HMAC_MD5_128 = 6,
    HMAC_SHA1_160 = 7,
    AES_CMAC_96 = 8,
    AES_128_GMAC = 9,
    AES_192_GMAC = 10,
    AES_256_GMAC = 11,
    HMAC_SHA2_256_128 = 12,
    HMAC_SHA2_384_192 = 13,
    HMAC_SHA2_512_256 = 14
};

/// Diffie-Hellman Group
enum D_H{
    DH_NONE = 0,
    MODP_768 = 1,
    MODP_1024 = 2,
    MODP_1536 = 5,
    MODP_2048 = 14,
    MODP_3072 = 15,
    MODP_4096 = 16,
    MODP_6144 = 17,
    MODP_8192 = 18,
    ECP_256 = 19,
    ECP_384 = 20,
    ECP_521 = 21,
    MODP_1024_PO_160 = 22,
    MODP_2O48_PO_224 = 23,
    MODP_2048_PO_256 = 24,
    ECP_192 = 25,
    ECP_224 = 26

};

/// Notify Message types
enum NOTIFY_MSG_TYPE{
    UNSUPPORTED_CRIT_PAYLOAD = 1,
    INVALID_IKE_SPI = 4,
    INVALID_MAJOR_VERSION = 5,
    INVALID_SYNTAX = 7,
    INVALID_MSG_ID = 9,
    INVALID_SPI = 11,
    NO_PROPOSAL_CHOSEN = 14,
    INVALID_KE_PAYLOAD = 17,
    AUTH_FAILED = 24,
    SINGLE_PAIR_REQUIRED = 34,
    NO_ADDITIONAL_SAS = 35,
    INTERNAL_ADDRESS_FAILURE = 36,
    FAILED_CP_REQUIRED = 37,
    TS_UNACCEPTABLE = 38,
    INVALID_SELECTORS = 39,
    TEMPORARY_FAILURE = 43,
    CHILD_SA_NOT_FOUND = 44
};

/**
 * @struct Isakmp Header 
 * @brief Container for a isakmp header
 */
struct rte_isakmp_hdr{
    /** initiator security parameter index */
    rte_be64_t initiator_spi; 
    /**  responder security parameter index */
    rte_be64_t responder_spi; 
    /** Payload ID */
    int8_t nxt_payload; 
    /** ike version which is split into major/minor, each taking up 4 bits */
    int8_t version;
    /**  type of exchange */
    int8_t exchange_type; 
    /** Options for the header */
    int8_t flags; 
    /** Message ID */
    rte_be32_t message_id;
    /**  Length of header */
    rte_be32_t total_length; 
};

/**
 * @struct Payload header
 * @brief Container for a paylaod header used in IKE packets
 */
struct isakmp_payload_hdr{
    /** What  comes after the payload */
    int8_t nxt_payload; 
    /** Critical bit */
    int8_t crit; 
    /** length of packet */
    uint16_t length;
};

/**
 * @struct Security Association Payload
 * @brief Container for a Security Association payload
 */
struct SA_payload{
    struct isakmp_payload_hdr *hdr;
};

struct proposal_hdr{
    /** whether if this is last proposal */
    int8_t nxt_payload;
    /**  must be 0 */
    int8_t reserved;
    /**  length of proposal */
    uint16_t len;
    /** proposal no. */
    int8_t proposal_num; 
    /** protocol used in proposal ie. IKE,AH,ESP */
    int8_t proto_id; 
    /** size of spi */
    int8_t spi_size; 
    /** number of transformations */
    int8_t num_transforms; 
};

struct proposal_struc{
    struct proposal_hdr *hdr;
    /** Sender's SPI */
    void* SPI; 
};

struct transform_hdr{
    /** whether if this is last transformations */
    int8_t nxt_payload; 
    /** must be 0 */
    int8_t reserved; 
    /**  length of payload */
    rte_be16_t len;
    /** transform type */
    int8_t type; 
    /**  must be 0 */
    int8_t reserved2; 
    /** Instance of transform type propsed */
    rte_be16_t transform_ID; 
};

struct attr{
    /** attribute type */
    int16_t type; 
    /** attribute value */
    int16_t value; 
};

struct transform_struc{
    struct transform_hdr *hdr;
    struct attr *attribute;
};


struct key_exchange{
    struct isakmp_payload_hdr hdr;
    rte_be16_t DH_GRP_NUM;
    int16_t reserved;
};

struct certificate{
    struct isakmp_payload_hdr *hdr;
    int8_t *type;
    /**  Certificate contained */
    void* encoding; 
};

struct nonce{
    struct isakmp_payload_hdr hdr;
};

struct notify_hdr{
    /** type of SA */
    int8_t protocol_id; 
    int8_t spi_size;
    /** Message type*/
    rte_be16_t msg_type;
};

struct notify{
    struct isakmp_payload_hdr *payload_hdr;
    struct notify_hdr *hdr;
    void* SPI;
    void* data;
};

struct delete{
    struct isakmp_payload_hdr hdr;
    int8_t proto_id;
    int8_t spi_size;
    rte_be16_t num_spis;
    void* SPI;
};

/** @struct tunnel
 *  @brief Container to store a tunnel between initiator and responder
 */
struct tunnel{
    /** initiator spi */
    uint64_t initiator_spi; 
    /** responder spi */
    uint64_t responder_spi; 
    /** client ip address */
    int client_ip; 
    /** host ip address */
    int host_ip; 
    /** client esp spi */
    uint32_t client_spi; 
    /** host esp spi */
    uint32_t host_spi; 
    /** client esp seq */
    uint32_t client_seq; 
    /** host esp seq */
    uint32_t host_seq; 
    /** dead peer detection flag */
    bool dpd; 
    /** auth flag */
    bool auth; 
    /** client flag to indicate tunnel was loaded from file */
    bool client_loaded; 
    /** host flag to indicate tunnel was loaded from file */
    bool host_loaded; 
    /** timeout counter */
    int timeout; 
    /** if count == 6, peer is deado */
    int dpd_count; 
};

/** Gets response flag of a packet. If 1, means the packet is a response else, the packet is a request
 * @param hdr IKE/isakmp headers of the packet
 * @return response flag of the packet
*/
int get_response_flag(struct rte_isakmp_hdr *hdr);

/** Gets version flag of a packet. If 1, means the sender can use a higher version of IKE
 * @param hdr IKE/isakmp headers of the packet
 * @return version flag of the packet
*/
int get_version_flag(struct rte_isakmp_hdr *hdr);

/** Gets initiator flag of a packet. If 1, means the packet is sent by the initiator else, the packet sent by the responder
 * @param isakmp_hdr IKE/isakmp headers of the packet
 * @return initiator flag of the packet
*/
int get_initiator_flag(struct rte_isakmp_hdr *isakmp_hdr);

/** Gets Exchange type of isakmp packet. Should only be used if logging the exchange type is needed
  * @param isakmp_hdr isakmp header of packet
  * @return String containing Exchange type of packet
  */
char* get_exchange_type (struct rte_isakmp_hdr *isakmp_hdr);

/** Gets Payload Type from a isakmp header as a string. Should only be used if logging the payload type is needed
  * @param isakmp_hdr isakmp header of packet
  * @returns a string containing the payload type
  */
char* get_ike_payload_type(struct rte_isakmp_hdr *isakmp_hdr);

/** Gets Payload Type from a isakmp payload header as a string. Should only be used if logging the payload type is needed
  * @param hdr isakmp header of packet
  * @returns a string containing the payload type
  */
char* get_nxt_payload(struct isakmp_payload_hdr *isakmp_payload_hdr);

/** Used to print important ike header instructions, can be converted to write log into file if needed
  * @param isakmp_hdr  isakmp header of packet
  */
void print_isakmp_headers_info(struct rte_isakmp_hdr *isakmp_hdr);

/**
 * Analyzes payload within an isakmp packet. Note that this function is recursive in nature and will continue until nxt_payload is 0 or packet is found to be malformed
 * @param pkt Pointer to packet buffer to be analyzed
 * @param isakmp_hdr pointer to isakmp headers in a packet
 * @param offset to start analyzing
 * @param nxt_payload Should take from isakmp_hdr or payload_hdr
 * @return 1 if packet is not tampered, 0 if otherrwise
 */
int analyse_isakmp_payload(struct rte_mbuf *pkt,struct rte_isakmp_hdr *isakmp_hdr,uint16_t offset,int nxt_payload);

/** converts ipv4 address into strings and place them in ip
 * @param addr ipv4 address to convert 
 * @param ip string to store the converted ip
 */
void get_ip_address_string(rte_be32_t addr,char *ip);

/** converts ipv6 address into strings and place them in ip
 * @param addr ipv6 address to convert 
 * @param ip string to store the converted ip
 */
void get_ipv6_address_string(uint8_t* addr,char *ip);

/** deletes tunnel from authenticated tunnels once session ends
 * @param initiator_spi initiator spi from ISAKMP/IKE header
 * @param responder_spi responder spi from ISAKMP/IKE header
 * @param src_addr source address of packet
 * @param dst_addr destination address of packet
 */
void delete_tunnel(uint64_t initiator_spi,uint64_t responder_spi,int src_addr,int dst_addr);

/**
 * Add tunnels to established tunnel array
 * @param tunnel tunnel to add
 */
void add_tunnel(struct tunnel* add);

/**
 * Remove tunnel from saved tunnel file
 * @param remove tunnel to remove
 */
void remove_tunnel(struct tunnel* remove);

/**
 * Load save tunnels from file and add them to established tunnels. The tunnels will have their client_loaded and host_laoded flag set
 */
void load_tunnel();

/**
 * Analyses a Key Exchange payload
 * @param pkt : pointer to packet used
 * @param offset: offset to paylaod header
 * @param isakmp_hdr pointer to isakmp headers
 * @param ipv4_hdr pointer to ipv4 headers
 * @returns 1 if there are no errors analyzing the packet, 0 if otherwise
 */
int analyse_KE(struct rte_mbuf *pkt,uint16_t offset,struct rte_isakmp_hdr *isakmp_hdr);

/**
 * Analyses a Authenticated and Encrypted payload. Note that whats inside cannot be analysed because it is encrypted
 * @param pkt : pointer to packet used
 * @param offset: offset to paylaod header
 * @param isakmp_hdr pointer to isakmp headers
 * @param ipv4_hdr pointer to ipv4 headers
 * @returns 1 if there are no errors analyzing the packet, 0 if otherwise
 */
int analyse_SK(struct rte_mbuf *pkt, uint16_t offset, struct rte_isakmp_hdr *isakmp_hdr);

/**
 * Analyses a Notify payload. If an error code is sent, should kill sesssion i think?
 * @param pkt : pointer to packet used
 * @param offset: offset to paylaod header
 * @param isakmp_hdr pointer to isakmp headers
 * @param ipv4_hdr pointer to ipv4 headers
 * @returns 1 if there are no errors analyzing the packet, 0 if otherwise
 */

int analyse_N(struct rte_mbuf *pkt, uint16_t offset,struct rte_isakmp_hdr *isakmp_hdr);

/**
 * Analyses a Certificate/Certificate request payload
 * @param pkt : pointer to packet used
 * @param offset: offset to paylaod header
 * @param isakmp_hdr pointer to isakmp headers
 * @param ipv4_hdr pointer to ipv4 headers
 * @returns 1 if there are no errors analyzing the packet, 0 if otherwise
 */
int analyse_CERT(struct rte_mbuf *pkt, uint16_t offset,struct rte_isakmp_hdr *isakmp_hdr);

/**
 * Get proposals and transformations found in a SA payload
 * @param pkt pointer to packet being analyzed
 * @param offset offset to SA hdr
 * @param proposals string array containing proposals
 * @param check int to check whether if packet is malformed
 * @returns number of proposals found
 */
int get_proposals(struct rte_mbuf *pkt, uint16_t offset,char***proposals,int *check);

/** 
 * Get Transformations found in a proposal and converts them into a string to log:
 * @param pkt pointer to packet to be analyzed
 * @param transformations pointer to Array contained in payload_struc object
 * @param offset Offset to transformation
 * @param size Number of transformations
 * @param buf string used to store transformations found
 * @param check int to check whether if packet is malformed
 */
void get_transformations(struct rte_mbuf *pkt, int offset,int size,char *buf,int* check);

/**
 * Analyses a Security Association payload
 * @param pkt : pointer to packet used
 * @param offset: offset to paylaod header
 * @param isakmp_hdr pointer to isakmp headers
 * @param ipv4_hdr pointer to ipv4 headers
 * @returns 1 if there are no errors analyzing the packet, 0 if otherwise
 */
int analyse_SA(struct rte_mbuf *pkt,uint16_t offset,struct rte_isakmp_hdr *isakmp_hdr);

/** 
 * checks whether if ike information in tunnel matches provided spis and ip address
 * @param initiator_spi initiator spi from ISAKMP/IKE header
 * @param responder_spi responder spi from ISAKMP/IKE header
 * @param src_addr source address of packet
 * @param dst_addr destination address of packet\
 * @param tunnel tunnel to check against
 * @returns 1 if information matches, 0 if otherwise
 */
int check_ike_spi(uint64_t initiator_spi,uint64_t responder_spi,int src_addr,int dst_addr,struct tunnel* tunnel);

/** 
 * checks whether if ike information in tunnel actually exists
 * @param isakmp_hdr isakmp header containing initiator and responder spis to check
 * @param ipv4_hdr IPV4 header containing respective ip addresses of client and host to check
 * @returns 1 if information matches, 0 if otherwise
 */
int check_if_tunnel_exists(struct rte_isakmp_hdr *isakmp_hdr,struct rte_ipv4_hdr *ipv4_hdr);
#endif

