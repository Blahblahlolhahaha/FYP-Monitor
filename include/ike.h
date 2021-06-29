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

        

static const int ESP_OFFSET = sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_ether_hdr) + sizeof(struct rte_udp_hdr);
static const int ISAKMP_OFFSET = sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_ether_hdr) + sizeof(struct rte_udp_hdr) + 4;
static const int first_payload_hdr_offset = ESP_OFFSET + 28;
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

enum EXCHANGE_TYPE{
    IKE_SA_INIT = 34,
    IKE_AUTH = 35,
    CREATE_CHILD_SA = 36,
    INFORMATIONAL = 37
};

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

enum TRANSFORM_TYPE{
    ENCR = 1, //Encryption Algorithm
    PRF = 2, //Pseudorandom function
    INTEG = 3, //Integrity Algorithm
    D_H = 4, // Diffie-Hellman Group
    ESN = 5 //Extended Sequence Numbers
};

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


struct rte_isakmp_hdr{
    rte_be64_t initiator_spi; // initiator security parameter index
    rte_be64_t responder_spi; // responder security parameter index
    int8_t nxt_payload; //Payload ID
    int8_t version; //ike version which is split into major/minor, each taking up 4 bits
    int8_t exchange_type; // type of exchange
    int8_t flags; //Options for the header
    rte_be32_t message_id; //Message ID
    rte_be32_t total_length; // Length of header
};


struct isakmp_payload_hdr{
    int8_t nxt_payload; //What  comes after the payload
    int8_t crit; //Critical bit
    uint16_t length;//length of packet
};


struct SA_payload{
    struct isakmp_payload_hdr *hdr;
};

struct proposal_hdr{
    int8_t nxt_payload; //whether if this is last proposal
    int8_t reserved; // must be 0
    uint16_t len; // length of proposal
    int8_t proposal_num; //proposal no.
    int8_t proto_id; //protocol used in proposal ie. IKE,AH,ESP
    int8_t spi_size; //size of spi
    int8_t num_transforms; //number of transformations
};

struct proposal_struc{
    struct proposal_hdr *hdr;
    void* SPI; //Sender's SPI
};

struct transform_hdr{
    int8_t nxt_payload; //whether if this is last transformations
    int8_t reserved; //must be 0
    rte_be16_t len; // length of payload
    int8_t type; //transform type
    int8_t reserved2; // must be 0
    rte_be16_t transform_ID; //Instance of transform type propsed
};

struct attr{
    int8_t type; //attribute type
    int8_t value; //attribute value
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
    void* encoding; // Certificate contained
};

struct nonce{
    struct isakmp_payload_hdr hdr;
};

struct notify_hdr{
    int8_t protocol_id; //type of SA
    int8_t spi_size;
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

struct tunnel{
    uint64_t client_spi;
    uint64_t host_spi;
    int client_ip;
    int host_ip;
    uint32_t client_seq;
    uint32_t host_seq;
    uint32_t client_esp_spi;
    uint32_t host_esp_spi;
    char *algo;
    int dpd_count; //if count == 6, peer is deado
    bool dpd;
    bool auth;
    int timeout;
};

/*flags in hdr:
RESPONSE
VERSION
INITIATOR
*/
int get_response_flag(struct rte_isakmp_hdr *hdr);

int get_version_flag(struct rte_isakmp_hdr *hdr);

int get_initiator_flag(struct rte_isakmp_hdr *hdr);

char *get_exchange_type (struct rte_isakmp_hdr *hdr);

char *get_ike_payload_type(struct rte_isakmp_hdr *hdr);

char *get_payload_nxt_payload(struct isakmp_payload_hdr *hdr);

void print_isakmp_headers_info(struct rte_isakmp_hdr *isakmp_hdr);

int analyse_isakmp_payload(struct rte_mbuf *pkt,struct rte_isakmp_hdr *isakmp_hdr,struct rte_ipv4_hdr *ipv4_hdr,uint16_t offset,int nxt_payload);

void get_ip_address_string(rte_be32_t ip_address,char *ip);

void delete_tunnel(uint64_t initiator_spi,uint64_t responder_spi,int src_addr,int dst_addr);
#endif

