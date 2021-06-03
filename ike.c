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

/// Gets Exchange type of isakmp packet
/// @return String containing Exchange type of packet
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

/// Gets Payload Type from a isakmp header
/// @returns a string containing the payload type
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

/**
 * Analyzes payload within an isakmp packet. Note that this function is recursive in nature and will continue until nxt_payload is 0
 * @param pkt Pointer to packet buffer to be analyzed
 * @param isakmp_hdr pointer to isakmp headers in a packet
 * @param offset to start analyzing
 * @param nxt_payload Should take from isakmp_hdr or payload_hdr
 */
void analyse_isakmp_payload(struct rte_mbuf *pkt,struct rte_isakmp_hdr *isakmp_hdr,struct rte_ipv4_hdr *ipv4_hdr,uint16_t offset,int nxt_payload){
    if(isakmp_hdr->exchange_type == IKE_SA_INIT){
        if(check_if_tunnel_exists(isakmp_hdr,ipv4_hdr)==0 && get_initiator_flag(isakmp_hdr) == 0 && isakmp_hdr->responder_spi != (rte_be64_t)0){
            struct tunnel new_tunnel;
            new_tunnel.host_ip = ipv4_hdr->src_addr;
            new_tunnel.client_ip = ipv4_hdr->dst_addr;

            new_tunnel.host_spi = isakmp_hdr->responder_spi;
            new_tunnel.client_spi = isakmp_hdr->initiator_spi;

            new_tunnel.dpd = false;
            new_tunnel.dpd_count = 0;

            new_tunnel.seq = 0;
            new_tunnel.algo = "";
            push(tunnels,&new_tunnel);
        };
    }
    
    switch(nxt_payload){
        case SA:
            analyse_SA(pkt,offset,isakmp_hdr,ipv4_hdr);
            break;

        case KE:
            analyse_KE(pkt,offset,isakmp_hdr,ipv4_hdr);
            break;

        case N:
            analyse_N(pkt,offset,isakmp_hdr,ipv4_hdr);
            break;

        case D:
            //Session is deleted
            printf("Session ended btw SPI: %lx, %lx", rte_be_to_cpu_64(isakmp_hdr->initiator_spi), rte_be_to_cpu_64(isakmp_hdr->responder_spi));
            delete_tunnel(isakmp_hdr,ipv4_hdr);
            break;
        
        case SK:
            analyse_SK(pkt,offset,isakmp_hdr,ipv4_hdr);
            break;
        
        default:{
            struct isakmp_payload_hdr *payload_hdr;
            payload_hdr = rte_pktmbuf_mtod_offset(pkt,struct isakmp_payload_hdr *,offset);
            if(nxt_payload != SKF){
                analyse_isakmp_payload(pkt,isakmp_hdr,ipv4_hdr,offset + rte_be_to_cpu_16(payload_hdr->length),payload_hdr->nxt_payload);
            }
            break;
        }
    }   

}
/**
 * Analyses a Security Association payload
 * @param pkt : pointer to packet used
 * @param offset: offset to paylaod headers
 * @param isakmp_hdr pointer to isakmp headers
 */
void analyse_SA(struct rte_mbuf *pkt,uint16_t offset,struct rte_isakmp_hdr *isakmp_hdr,struct rte_ipv4_hdr *ipv4_hdr){
    struct SA_payload *payload;
    payload = malloc(sizeof(struct SA_payload));
    if(payload){
        payload->hdr = rte_pktmbuf_mtod_offset(pkt,struct isakmp_payload_hdr *,offset); //get payload header
        printf("Size: %x\n",rte_be_to_cpu_16(payload->hdr->length));
        payload->proposals = malloc(sizeof(struct Array));
        if(payload->proposals){
            void *objects[] = {0};
            initArray(payload->proposals,0,objects,false,sizeof(struct proposal_struc));
            get_proposals(pkt,payload->proposals,offset + sizeof(struct isakmp_payload_hdr)); //get proposals and their respective transformations
        }
        if(payload->hdr->nxt_payload !=0){
            analyse_isakmp_payload(pkt,isakmp_hdr,ipv4_hdr,offset + rte_be_to_cpu_16(payload->hdr->length),payload->hdr->nxt_payload); //continue analyzing packet
        }
    }
    // clean up
    clean_proposals(payload->proposals);
    free(payload);
}

/**
 * Analyses a Key Exchange payload
 * @param pkt : pointer to packet used
 * @param offset: offset to paylaod headers
 * @param isakmp_hdr pointer to isakmp headers
 */
void analyse_KE(struct rte_mbuf *pkt,uint16_t offset,struct rte_isakmp_hdr *isakmp_hdr,struct rte_ipv4_hdr *ipv4_hdr){
    struct key_exchange* payload;
    payload = rte_pktmbuf_mtod_offset(pkt,struct key_exchange *,offset);
    printf("Key Exchange: %u\n",rte_be_to_cpu_16(payload->DH_GRP_NUM));
    
    if(payload->hdr.nxt_payload !=0){
        analyse_isakmp_payload(pkt,isakmp_hdr,ipv4_hdr,offset + rte_be_to_cpu_16(payload->hdr.length),payload->hdr.nxt_payload);
    }
}

/**
 * Analyses a Authenticated and Encrypted payload. Note that whats inside cannot be analysed because it is encrypted
 * @param pkt : pointer to packet used
 * @param offset: offset to paylaod headers
 * @param isakmp_hdr pointer to isakmp headers
 */
void analyse_SK(struct rte_mbuf *pkt, uint16_t offset, struct rte_isakmp_hdr *isakmp_hdr,struct rte_ipv4_hdr *ipv4_hdr){
    struct isakmp_payload_hdr *payload_hdr;
    payload_hdr = rte_pktmbuf_mtod_offset(pkt,struct isakmp_payload_hdr *,offset);
    for(int i = 1;i <= tunnels->size; i++){
        struct tunnel *tunnel = tunnels->array[i];
        
        if(check_ike_spi(isakmp_hdr,ipv4_hdr,tunnel) == 1){
            printf("%u\n",offset);
            if(payload_hdr->nxt_payload == NO && isakmp_hdr->exchange_type == INFORMATIONAL){
                //Dead peer detection
                if(get_initiator_flag(isakmp_hdr) == 1){
                    // DPD start/continue
                    tunnel->dpd_count += 1;
                    if(tunnel->dpd_count == 1){
                        tunnel->dpd = true;
                    }
                    if(tunnel->dpd_count == 6){
                        // Peer is dead and session should be removed
                        printf("Session ended btw SPI: %lx, %lx", rte_be_to_cpu_64(isakmp_hdr->initiator_spi), rte_be_to_cpu_64(isakmp_hdr->responder_spi));
                        removeIndex(tunnels,i-1);
                    }
                }
                else if(get_response_flag(isakmp_hdr) == 1){
                    //Peer has responded and is not dead 
                    tunnel->dpd_count = 0;
                    tunnel->dpd = false;
                }
            }
            else if(payload_hdr->nxt_payload == D && isakmp_hdr->exchange_type == INFORMATIONAL){
                printf("Session ended btw SPI: %lx, %lx", rte_be_to_cpu_64(isakmp_hdr->initiator_spi), rte_be_to_cpu_64(isakmp_hdr->responder_spi));
                delete_tunnel(isakmp_hdr,ipv4_hdr);
            }
            else if(payload_hdr->nxt_payload == AUTH && isakmp_hdr->exchange_type == IKE_AUTH){
                if(get_response_flag(isakmp_hdr) == 1){
                    char* src_ip[15];
                    char* dst_ip[15];
                    if(src_ip && dst_ip){
                        get_ip_address_string(ipv4_hdr->src_addr,src_ip);
                        get_ip_address_string(ipv4_hdr->dst_addr,dst_ip);
                        printf("IKE Authentication between %s and %s succeeded\n", src_ip, dst_ip);
                    }
                    
                }
            }
            
        }
            
    }
    
}

/**
 * Analyses a Notify payload. If an error code is sent, should kill sesssion i think?
 * @param pkt : pointer to packet used
 * @param offset: offset to paylaod headers
 * @param isakmp_hdr pointer to isakmp headers
 */

void analyse_N(struct rte_mbuf *pkt, uint16_t offset,struct rte_isakmp_hdr *isakmp_hdr,struct rte_ipv4_hdr *ipv4_hdr){
    struct notify *payload;
    bool error = false;
    bool special_error = false;
    payload = malloc(sizeof(struct notify_hdr));
    char *msg;
    char failed_msg[128] = "";
    strcat(failed_msg,"IKE failed with error:");
    if(payload){
        payload->payload_hdr = rte_pktmbuf_mtod_offset(pkt,struct isakmp_payload_hdr *,offset);
        payload->hdr = rte_pktmbuf_mtod_offset(pkt,struct notify_hdr *,offset + sizeof(struct isakmp_payload_hdr));
        switch(rte_be_to_cpu_16(payload->hdr->msg_type)){
            case INVALID_KE_PAYLOAD:
                strcat(failed_msg,"INVALID_KE_PAYLAOD\n");
                error = true;
                break;
            case INVALID_MAJOR_VERSION:
                strcat(failed_msg,"INVALID_MAJOR_VERSION\n");
                error = true;
                break;
            case UNSUPPORTED_CRIT_PAYLOAD:
                strcat(failed_msg,"UNSUPPORTED_CRIT_PAYLOAD\n");
                error = true;
                break;
            case INVALID_SYNTAX:
                strcat(failed_msg,"INVALID_SYNTAX\n");
                error = true;
                break;
            case INVALID_SPI:
                msg = "Invalid SPI detected by firewall\n";
                special_error = true;
                break;
            case INVALID_MSG_ID:
                msg = "Invalid Message ID detected by firewall\n";
                special_error = true;
                break;
            case NO_PROPOSAL_CHOSEN:
                strcat(failed_msg,"NO_PROPOSAL_CHOSEN\n");
                error = true;
                break;
            case AUTH_FAILED:
                strcat(failed_msg,"INVALID_SYNTAX\n");
                error = true;
                break;
            case SINGLE_PAIR_REQUIRED:
                strcat(failed_msg,"SINGLE_PAIR_REQUIRED\n");
                error = true;
                break;
            case NO_ADDITIONAL_SAS:
                strcat(failed_msg,"SINGLE_PAIR_REQUIRED\n");
                error = true;
                break;
            case INTERNAL_ADDRESS_FAILURE:
                strcat(failed_msg,"INTERNAL_ADDRESS_FAILURE\n");
                error = true;
                break;
            case FAILED_CP_REQUIRED:
                strcat(failed_msg,"FAILED_CP_REQUIRED\n");
                error = true;
                break;
            case TS_UNACCEPTABLE:
                strcat(failed_msg,"TS_UNACCEPTABLE\n");
                error = true;
                break;
            case INVALID_SELECTORS:
                strcat(failed_msg,"INVALID_SELECTORS\n");
                error = true;
                break;
            case TEMPORARY_FAILURE:
                strcat(failed_msg,"TEMPORARY_FAILURE\n");
                error = true;
                break;
            case CHILD_SA_NOT_FOUND:
                strcat(failed_msg,"CHILD_SA_NOT_FOUND\n");
                error = true;
                break;
        }
    }
    if(error){
        delete_tunnel(isakmp_hdr,ipv4_hdr);
        printf("%s",failed_msg);
    }
    else if(special_error){
        printf("%s",msg);
    }
    else if(payload->payload_hdr->nxt_payload != NO){
        analyse_isakmp_payload(pkt,isakmp_hdr,ipv4_hdr,offset + rte_be_to_cpu_16(payload->payload_hdr->length),payload->payload_hdr->nxt_payload);
    }
    free(payload);
}

/**
 * Get proposals and transformations found in a SA payload and place them in an Array object
 * @param pkt pointer to packet being analyzed
 * @param proposals pointer to Array object used in a SA_paylaod struct
 * @param offset offset to SA hdr
 */
void get_proposals(struct rte_mbuf *pkt, struct Array *proposals, uint16_t offset){
    struct proposal_struc *proposal;
    proposal = malloc(3 * __SIZEOF_POINTER__);
    if(proposal){
        do{
            // printf("current offset: %u",offset);
            proposal->hdr = rte_pktmbuf_mtod_offset(pkt,struct proposal_hdr *, offset);
            proposal->transformations = malloc(sizeof(struct Array));
            
            // printf("length: %x\n", rte_be_to_cpu_16(proposal->hdr->len));
            // printf("proposal_num: %x\n",proposal->hdr->proposal_num);
            // printf("No. Transformations: %d",proposal->hdr->num_transforms);
            // printf("reserve %x\n\n",proposal->hdr->reserved);
            uint16_t transformation_offset = offset + 8 + proposal->hdr->spi_size;
            if(proposal->transformations){
                //get proposed transformations
                get_transformations(pkt,proposal->transformations,transformation_offset,proposal->hdr->num_transforms);
            }
            else{
                printf("Failed to allocate memory. Exiting\n");
                exit(1);
            }
            offset += rte_be_to_cpu_16(proposal->hdr->len); //add offset for nxt proposal
            push(proposals,(void*)proposal);
            
        }while(proposal->hdr->nxt_payload != (int8_t)0);
    }
    else{
        printf("Failed to allocate memory. Exiting\n");
        exit(1);
    }
    
}

/** 
 * Get Transformations found in a proposal and place them in an array:
 * @param pkt pointer to packet to be analyzed
 * @param transformations pointer to Array contained in payload_struc object
 * @param offset Offset to transformation
 * @param size Number of transformations
 */
void get_transformations(struct rte_mbuf *pkt, struct Array *transformations,int offset,int size){
    struct transform_struc *transform = malloc(2 * __SIZEOF_POINTER__);
    if(transform){
        int actual = 0;
        void *objects[] = {0};
        initArray(transformations,size,objects,false,sizeof(struct transform_struc));
        do{
            transform->hdr = rte_pktmbuf_mtod_offset(pkt,struct transform_hdr *, offset);
            actual++;
            // printf("\n===================\nTransform %d\n===================",actual);
            // printf("\n| Type: %u",transform->hdr->type);
            // printf("\n| Type ID: %x",rte_be_to_cpu_16(transform->hdr->transform_ID));
            // printf("\n================================\n");
            if(transform->hdr->len != 8){
                //get attributes for transformation usually key length
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

/** 
 * Free up memory allocated to proposals and transformations
 */
void clean_proposals(struct Array* proposals){
    for(int i = 0;i< proposals->size;i++){
        struct proposal_struc *proposal =  proposals->array[i+1]; 
        clearArray(proposal->transformations);
        free(proposal->transformations);
        free(proposal);
    }
    clearArray(proposals);
    free(proposals);

}

void delete_tunnel(struct rte_isakmp_hdr *isakmp_hdr,struct rte_ipv4_hdr *ipv4_hdr){
    for(int i = 1;i <= tunnels->size; i++){
        struct tunnel *tunnel = tunnels->array[i];
        
        if(check_ike_spi(isakmp_hdr,ipv4_hdr,tunnel) == 1){
            
            // removeIndex(tunnels,i-1);
            break;
        }
    }
}

int check_ike_spi(struct rte_isakmp_hdr *isakmp_hdr,struct rte_ipv4_hdr *ipv4_hdr,struct tunnel* tunnel){
    return (tunnel->client_spi == isakmp_hdr->initiator_spi 
                && tunnel->host_spi == isakmp_hdr->responder_spi) && ((tunnel->client_ip == ipv4_hdr->src_addr && tunnel->host_ip == ipv4_hdr->dst_addr) || 
                (tunnel->host_ip == ipv4_hdr->src_addr && tunnel->client_ip == ipv4_hdr->dst_addr)) ? 1 : 0;
}

int check_if_tunnel_exists(struct rte_isakmp_hdr *isakmp_hdr,struct rte_ipv4_hdr *hdr){
    for(int i = 1;i<tunnels->size;i++){
        struct tunnel *tunnel = (struct tunnel *)tunnels->array[i];
        if(check_ike_spi(isakmp_hdr,hdr,tunnel) == 1){
            return 1;
        }
    }
    return 0;
}

void get_ip_address_string(rte_be32_t ip_address,char *ip){
    int bit4 = ip_address >> 24 & 0xFF;
    int bit3 = ip_address >> 16 & 0xFF;
    int bit2 = ip_address >> 8 & 0xFF;
    int bit1 = ip_address & 0xFF;
    sprintf(ip,"%u.%u.%u.%u",bit1,bit2,bit3,bit4);
}   