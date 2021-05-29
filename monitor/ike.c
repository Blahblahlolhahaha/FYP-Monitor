#include "include/ike.h"

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
    char *nxt_payload = get_payload_type(isakmp_hdr);
    if(nxt_payload){
        printf("Paylaod Type: %s\n", nxt_payload);
    }
    else{
        printf("Packet has invalid exchange type!\n");
    }
    char *exchange_type = get_exchange_type(isakmp_hdr);
    if(exchange_type){
        printf("Exchange Type: %s\n", exchange_type);
    }
    else{
        printf("Invalid Exchange Type!");
    }
    printf("Message ID: %04x\n\n",rte_be_to_cpu_32(isakmp_hdr->message_id));
}