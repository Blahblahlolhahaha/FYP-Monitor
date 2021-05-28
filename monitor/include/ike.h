#ifndef IKE_H
#define IKE_H

#include <stdint.h>
#include <inttypes.h>
#include <getopt.h>

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

/*flags in hdr:
RESPONSE
VERSION
INITIATOR
*/
int get_response_flag(struct rte_isakmp_hdr *hdr){
    //if 1, this packet is used to respond
    return (hdr->flags >> 5) & 1;
}

int get_version_flag(struct rte_isakmp_hdr *hdr){
    //if 1, responder can use higher version
    return (hdr->flags >> 4) & 1;
}

int get_initiator_flag(struct rte_isakmp_hdr *hdr){
    //if 1, this packet is used to init
    return (hdr->flags >> 3) & 1;
}

#endif
