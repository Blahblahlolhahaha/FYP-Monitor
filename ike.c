#include "include/ike.h"

static const int ESP_OFFSET = sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_ether_hdr) + sizeof(struct rte_udp_hdr);
static const int ISAKMP_OFFSET = sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_ether_hdr) + sizeof(struct rte_udp_hdr) + 4;


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

char *get_exchange_type (struct rte_isakmp_hdr *hdr){
    switch (hdr->exchange_type){

        case IKE_SA_INIT:
            return "IKE_SA_INIT";
            break;

        case IKE_AUTH:
            return "IKE_AUTH";
            break;
        
        case CREATE_CHILD_SA:
            return "CREATE_CHILD_SA";
            break;
        
        case INFORMATIONAL:
            return "INFORMATIONAL";
            break;
        
        default:
            return NULL;
            break;
    }
}

char *get_payload_type(struct rte_isakmp_hdr *hdr){
    switch (hdr->nxt_payload){
        case NO:
            return "No Next Payload";
            break;
        case SA:
            return "Security Association";
            break;
        case KE:
            return "Key Exchange";
            break;
        case IDI:
            return "Identification - Initiator";
            break;
        case IDR:
            return "Identification - Responder";
            break;
        case CERT:
            return "Certificate";
            break;
        case CERTREQ:
            return "Certificate Request";
            break;
        case AUTH:
            return "Authentication";
            break;
        case NONCE:
            return "Nonce";
            break;
        case N:
            return "Notify";
            break;
        case D:
            return "Delete";
            break;
        case V:
            return "Vendor ID";
            break;
        case TSI:
            return "Traffic Selector - Initiator";
            break;
        case TSR:
            return "Traffic Selector - Responder";
            break;
        case SK:
            return "Encrypted and Authenticated";
            break;
        case SKF:
            return "Encrypted and Authenticated Fragment";
            break;
        case CP:
            return "Configuration";
            break;
        case EAP:
            return "Extensible Authentication";
            break;
        default:
            return NULL;
            break;
    }
}

void print_isakmp_headers_info(struct rte_isakmp_hdr *isakmp_hdr){
    printf("Initiator SPI: %lx\n", rte_be_to_cpu_64(isakmp_hdr->initiator_spi));
    printf("Responder SPI: %lx\n", rte_be_to_cpu_64(isakmp_hdr->responder_spi));
    printf("%d",get_initiator_flag(isakmp_hdr));
    printf("%d",get_response_flag(isakmp_hdr));
    printf("Message ID: %04x\n\n",rte_be_to_cpu_32(isakmp_hdr->message_id));
}

void analyse_isakmp_payload(struct rte_mbuf *pkt,struct rte_isakmp_hdr *hdr,struct rte_ipv4_hdr *ipv4_hdr){
    char* exchange_type = get_exchange_type(hdr);
    if(strcmp(exchange_type,"IKE_SA_INIT") == 0){
        if(get_initiator_flag(hdr) == 1){
            int srcip_bit4 = ipv4_hdr->src_addr >> 24 & 0xFF;
            int srcip_bit3 = ipv4_hdr->src_addr >> 16 & 0xFF;
            int srcip_bit2 = ipv4_hdr->src_addr >> 8 & 0xFF;
            int srcip_bit1 = ipv4_hdr->src_addr & 0xFF;
            
            int dstip_bit4 = ipv4_hdr->dst_addr >> 24 & 0xFF;
            int dstip_bit3 = ipv4_hdr->dst_addr >> 16 & 0xFF;
            int dstip_bit2 = ipv4_hdr->dst_addr >> 8 & 0xFF;
            int dstip_bit1 = ipv4_hdr->dst_addr & 0xFF;


            printf("%u.%u.%u.%u is trying to initiate IKE exchange with %u.%u.%u.%u", srcip_bit4,srcip_bit3,srcip_bit2,srcip_bit1,dstip_bit4,dstip_bit3,dstip_bit2,dstip_bit1);
        }
        else{
            switch(hdr->nxt_payload){
            case SA:
                struct SA_payload *payload = malloc(sizeof(struct SA_payload));
                if(payload){
                    payload->hdr = rte_pktmbuf_mtod_offset(pkt,struct isakmp_payload_hdr *, ESP_OFFSET);
                    payload->payloads = malloc(sizeof(struct Array));
                    if(payload->payloads){
                        
                    }
                }
            }   
        }
        
    }

}
