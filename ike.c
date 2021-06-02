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
    printf("Initiator: %d\n",get_initiator_flag(isakmp_hdr));
    printf("Response: %d\n",get_response_flag(isakmp_hdr));
    printf("Message ID: %04x\n\n",rte_be_to_cpu_32(isakmp_hdr->message_id));
}

void analyse_isakmp_payload(struct rte_mbuf *pkt,int nxt_payload,uint16_t offset){
    switch(nxt_payload){
        case SA:
            analyse_SA(pkt,offset);
            break;

        case KE:
            analyse_KE(pkt,offset);
            break;
    }   

}

void analyse_SA(struct rte_mbuf *pkt,uint16_t offset){
    struct SA_payload *payload;
    payload = malloc(sizeof(struct SA_payload));
    if(payload){
        payload->hdr = rte_pktmbuf_mtod_offset(pkt,struct isakmp_payload_hdr *,offset);
        printf("Size: %x\n",rte_be_to_cpu_16(payload->hdr->length));
        payload->proposals = malloc(sizeof(struct Array));
        if(payload->proposals){
            void *objects[] = {0};
            initArray(payload->proposals,0,objects,false,sizeof(struct proposal_struc));
            get_proposals(pkt,payload->proposals);
        }
        if(payload->hdr->nxt_payload !=0){
            analyse_isakmp_payload(pkt,payload->hdr->nxt_payload,offset + rte_be_to_cpu_16(payload->hdr->length));
        }
    }
}

void analyse_KE(struct rte_mbuf *pkt,uint16_t offset){
    struct key_exchange *payload;
    payload = malloc(sizeof(struct key_exchange));
    if(payload){
        payload = rte_pktmbuf_mtod_offset(pkt,struct key_exchange *,offset);
        printf("Key Exchange: %u\n",rte_be_to_cpu_16(payload->DH_GRP_NUM));
    }
}

void get_proposals(struct rte_mbuf *pkt, struct Array *proposals){
    int proposal_offset = first_payload_hdr_offset + sizeof(struct isakmp_payload_hdr);
    struct proposal_struc *proposal;
    proposal = malloc(3 * __SIZEOF_POINTER__);
    if(proposal){
        do{
            proposal->hdr = rte_pktmbuf_mtod_offset(pkt,struct proposal_hdr *, proposal_offset);
            proposal->transformations = malloc(sizeof(struct Array));
            int transformation_offset = proposal_offset + 8 + proposal->hdr->spi_size;
            if(proposal->transformations){
                get_transformations(pkt,proposal->transformations,transformation_offset,proposal->hdr->num_transforms);
            }
            else{
                printf("Failed to allocate memory. Exiting\n");
                exit(1);
            }
            proposal_offset += rte_be_to_cpu_16(proposal->hdr->len);
            push(proposals,(void*)proposal);
            for(int i = 0;i< proposals->size;i++){
                struct proposal_struc *proposal =  proposals->array[i+1]; 
                printf("Next Payload: %x\n",proposal->hdr->nxt_payload);
                printf("length: %x\n", rte_be_to_cpu_16(proposal->hdr->len));
                printf("proposal_num: %x\n",proposal->hdr->proposal_num);
                printf("reserve %x\n",proposal->hdr->reserved);
            }
        }while(proposal->hdr->nxt_payload != 0);
    }
    else{
        printf("Failed to allocate memory. Exiting\n");
        exit(1);
    }
    
}

void get_transformations(struct rte_mbuf *pkt, struct Array *transformations,int offset,int size){
    struct transform_struc *transform = malloc(2 * __SIZEOF_POINTER__);
    if(transform){
        int actual = 0;
        void *objects[] = {0};
        initArray(transformations,size,objects,false,sizeof(struct transform_struc));
        do{
            printf("sad\n");
            transform->hdr = rte_pktmbuf_mtod_offset(pkt,struct transform_hdr *, offset);
            actual++;
            printf("\n===================\nTransform %d\n===================",actual);
            printf("\n| Type: %u",transform->hdr->type);
            printf("\n| Type ID: %x",rte_be_to_cpu_16(transform->hdr->transform_ID));
            printf("\n================================\n");
            if(transform->hdr->len != 8){
                struct attr *attribute  = rte_pktmbuf_mtod_offset(pkt,struct attr *,offset + 8);
                transform->attribute = attribute;
            }
            push(transformations,transform);
            
            if(actual > size){
                printf("Too many transformations!");
            }
            offset += rte_be_to_cpu_16(transform->hdr->len);
        }while(transform->hdr->nxt_payload != 0);
    }

}