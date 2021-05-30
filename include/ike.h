#ifndef IKE_H
#define IKE_H

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <getopt.h>
#include <rte_byteorder.h>

struct rte_isakmp_hdr{
    rte_be64_t initiator_spi;
    rte_be64_t responder_spi;
    int8_t nxt_payload;
    int8_t version;
    int8_t exchange_type;
    int8_t flags;
    rte_be32_t message_id;
    rte_be32_t total_length;
};

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

/*flags in hdr:
RESPONSE
VERSION
INITIATOR
*/
int get_response_flag(struct rte_isakmp_hdr *hdr);

int get_version_flag(struct rte_isakmp_hdr *hdr);

int get_initiator_flag(struct rte_isakmp_hdr *hdr);

char *get_exchange_type (struct rte_isakmp_hdr *hdr);

char *get_payload_type(struct rte_isakmp_hdr *hdr);

void print_isakmp_headers_info(struct rte_isakmp_hdr *isakmp_hdr);

#endif

