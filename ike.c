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
/// Should only be used if logging the exchange type is needed
/// @return String containing Exchange type of packet
char *get_exchange_type (struct rte_isakmp_hdr *hdr){
    int index  = hdr->exchange_type - 34;
    if(index > 0 && index - 34 < 4){
        return exchange_types[index];
    }
}

/// Gets Payload Type from a isakmp header as a string
/// Should only be used if logging the payload type is needed
/// @returns a string containing the payload type
char *get_ike_payload_type(struct rte_isakmp_hdr *hdr){
    if(hdr->nxt_payload == NO){
        return "No Next Payload";
    }
    else if(hdr->nxt_payload == SKF){
        return "Encrypted and Authenticated Fragment";
    }
    else if(hdr->nxt_payload >= SA && hdr->nxt_payload <= EAP){
        return payload_types[hdr->nxt_payload - 33];
    }
    else{
        return NULL;
    }
}

/// Gets Payload Type from a isakmp payload header as a string
/// Should only be used if logging the payload type is needed
/// @returns a string containing the payload type
char *get_payload_nxt_payload(struct isakmp_payload_hdr *hdr){
    if(hdr->nxt_payload == NO){
        return "No Next Payload";
    }
    else if(hdr->nxt_payload == SKF){
        return "Encrypted and Authenticated Fragment";
    }
    else if(hdr->nxt_payload >= SA && hdr->nxt_payload <= EAP){
        return payload_types[hdr->nxt_payload - 33];
    }
    else{
        return NULL;
    }
}

void print_isakmp_headers_info(struct rte_isakmp_hdr *isakmp_hdr){
    //used to print important ike header instructions, can be converted to log into file if needed
    printf("Initiator SPI: %lx\n", rte_be_to_cpu_64(isakmp_hdr->initiator_spi));
    printf("Responder SPI: %lx\n", rte_be_to_cpu_64(isakmp_hdr->responder_spi));
    printf("Initiator: %d\n",get_initiator_flag(isakmp_hdr));
    printf("Response: %d\n",get_response_flag(isakmp_hdr));
    printf("Message ID: %04x\n\n",rte_be_to_cpu_32(isakmp_hdr->message_id));
    printf("Exchange type: %s", get_exchange_type(isakmp_hdr));
}

/**
 * Analyzes payload within an isakmp packet. Note that this function is recursive in nature and will continue until nxt_payload is 0
 * @param pkt Pointer to packet buffer to be analyzed
 * @param isakmp_hdr pointer to isakmp headers in a packet
 * @param offset to start analyzing
 * @param nxt_payload Should take from isakmp_hdr or payload_hdr
 * @return 1 if packet is legit, 0 if otherrwise
 */
int analyse_isakmp_payload(struct rte_mbuf *pkt,struct rte_isakmp_hdr *isakmp_hdr,struct rte_ipv4_hdr *ipv4_hdr,uint16_t offset,int nxt_payload){
    int check = 1;
    if(isakmp_hdr->exchange_type == IKE_SA_INIT){
        if(check_if_tunnel_exists(isakmp_hdr,ipv4_hdr)==0 && get_initiator_flag(isakmp_hdr) == 0 && isakmp_hdr->responder_spi != (rte_be64_t)0){
            //Only if server responds then tunnel should be considered legit
            struct tunnel new_tunnel;
            new_tunnel.host_ip = ipv4_hdr->src_addr;
            new_tunnel.client_ip = ipv4_hdr->dst_addr;

            new_tunnel.host_spi = isakmp_hdr->responder_spi;
            new_tunnel.client_spi = isakmp_hdr->initiator_spi;
            new_tunnel.host_esp_spi = 0;
            new_tunnel.client_esp_spi = 0;

            new_tunnel.dpd = false;
            new_tunnel.dpd_count = 0;

            new_tunnel.client_seq = 0;
            new_tunnel.host_seq = 0;
            new_tunnel.algo = "";
            push(tunnels,&new_tunnel);
            printf("%x\n",check_if_tunnel_exists(isakmp_hdr,ipv4_hdr));
        };
    }
   
    if((isakmp_hdr->exchange_type == IKE_SA_INIT && check_if_tunnel_exists(isakmp_hdr,ipv4_hdr)==0) || (check_if_tunnel_exists(isakmp_hdr,ipv4_hdr)==1)){
        // If tunnel does not exist, should only be IKE_SA_INIT, else sus
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
                printf("Session ended btw SPI: %lx, %lx\n", rte_be_to_cpu_64(isakmp_hdr->initiator_spi), rte_be_to_cpu_64(isakmp_hdr->responder_spi));
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
    else{
        printf("Unauthorised Packet\n");
        check = 0;
    }
    return check;

}
/**
 * Analyses a Security Association payload
 * @param pkt : pointer to packet used
 * @param offset: offset to paylaod headers
 * @param isakmp_hdr pointer to isakmp headers
 */
void analyse_SA(struct rte_mbuf *pkt,uint16_t offset,struct rte_isakmp_hdr *isakmp_hdr,struct rte_ipv4_hdr *ipv4_hdr){
    struct isakmp_payload_hdr *payload;
    payload = rte_pktmbuf_mtod_offset(pkt,struct isakmp_payload_hdr *,offset); //get payload header
    get_proposals(pkt,offset + sizeof(struct isakmp_payload_hdr)); //get proposals and their respective transformations
    if(payload->nxt_payload !=0){
        analyse_isakmp_payload(pkt,isakmp_hdr,ipv4_hdr,offset + rte_be_to_cpu_16(payload->length),payload->nxt_payload); //continue analyzing packet
    }
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
            //nid to ensure spi is the same
            if(payload_hdr->nxt_payload == NO && isakmp_hdr->exchange_type == INFORMATIONAL){
                //Dead peer detection
                //responder will send the request and initiator has to respond within 6 requests
                if(get_initiator_flag(isakmp_hdr) == 0 && get_response_flag(isakmp_hdr) == 0){
                    // DPD start/continue
                    tunnel->dpd_count += 1;
                    if(tunnel->dpd_count == 1){
                        tunnel->dpd = true;
                    }
                    printf("dpd count: %d\n",tunnel->dpd_count);
                    if(tunnel->dpd_count == 6){
                        // Peer is dead and session should be removed
                        printf("Session ended btw SPI: %lx, %lx\n", rte_be_to_cpu_64(isakmp_hdr->initiator_spi), rte_be_to_cpu_64(isakmp_hdr->responder_spi));
                        removeIndex(tunnels,i-1);
                    }
                }
                else if(get_initiator_flag(isakmp_hdr) == 1 && get_response_flag(isakmp_hdr) == 1){
                    //Peer has responded and is not dead , hence refresh dpd is reset
                    printf("refresh\n");
                    tunnel->dpd_count = 0;
                    tunnel->dpd = false;
                }
            }
            else if(payload_hdr->nxt_payload == D && isakmp_hdr->exchange_type == INFORMATIONAL){
                //Either side ends connection, so delete tunnel
                printf("Session ended btw SPI: %lx, %lx\n", rte_be_to_cpu_64(isakmp_hdr->initiator_spi), rte_be_to_cpu_64(isakmp_hdr->responder_spi));
                delete_tunnel(isakmp_hdr,ipv4_hdr);
            }
            else if(payload_hdr->nxt_payload == AUTH && isakmp_hdr->exchange_type == IKE_AUTH){
                //99.9% means authenticated once responder sends this payload unless server kena gon
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
    char *msg = malloc(256);
    char failed_msg[128] = "";
    strcat(failed_msg,"IKE failed with error:");
    if(payload && msg){
        payload->payload_hdr = rte_pktmbuf_mtod_offset(pkt,struct isakmp_payload_hdr *,offset);
        payload->hdr = rte_pktmbuf_mtod_offset(pkt,struct notify_hdr *,offset + sizeof(struct isakmp_payload_hdr));
        if(rte_be_to_cpu_16(payload->hdr->msg_type) <= 44){
            //so far anything above 44 isnt done theres the 16k series of msg types;
            char * msg_type = notify_msg_type[rte_be_to_cpu_16(payload->hdr->msg_type) - 1];
            if(strcmp(msg_type, "\0") != 0 && rte_be_to_cpu_16(payload->hdr->msg_type) !=  INVALID_SPI && rte_be_to_cpu_16(payload->hdr->msg_type) !=  INVALID_MSG_ID){
                //Error codes related to auth
                error = true;
                strcat(failed_msg,msg_type);
            }
            //other error codes
            else if(rte_be_to_cpu_16(payload->hdr->msg_type) ==  INVALID_SPI){
                msg = "Invalid SPI detected by firewall\n";
                special_error = true;
            }
            else if(rte_be_to_cpu_16(payload->hdr->msg_type) ==  INVALID_MSG_ID){
                msg = "Invalid Message ID detected by firewall\n";
                special_error = true;
            }
            if(error){
                delete_tunnel(isakmp_hdr,ipv4_hdr);
                printf("%s",failed_msg);
            }
            else if(special_error){
                printf("%s",msg);
            }
        }
    }
    if(payload->payload_hdr->nxt_payload != NO){
        analyse_isakmp_payload(pkt,isakmp_hdr,ipv4_hdr,offset + rte_be_to_cpu_16(payload->payload_hdr->length),payload->payload_hdr->nxt_payload);
    }
    free(payload);
    free(msg);
    
}

/**
 * Get proposals and transformations found in a SA payload
 * @param pkt pointer to packet being analyzed
 * @param proposals pointer to Array object used in a SA_paylaod struct
 * @param offset offset to SA hdr
 */
void get_proposals(struct rte_mbuf *pkt, uint16_t offset){
    struct proposal_struc *proposal;
    proposal = malloc(3 * __SIZEOF_POINTER__);
    if(proposal){
        do{
            
            // printf("current offset: %u",offset);
            proposal->hdr = rte_pktmbuf_mtod_offset(pkt,struct proposal_hdr *, offset);
            
            // printf("length: %x\n", rte_be_to_cpu_16(proposal->hdr->len));
            // printf("proposal_num: %x\n",proposal->hdr->proposal_num);
            // printf("No. Transformations: %d",proposal->hdr->num_transforms);
            // printf("reserve %x\n\n",proposal->hdr->reserved);
            uint16_t transformation_offset = offset + 8 + proposal->hdr->spi_size;
            get_transformations(pkt,transformation_offset,proposal->hdr->num_transforms);
            offset += rte_be_to_cpu_16(proposal->hdr->len); //add offset for nxt proposal
            
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
void get_transformations(struct rte_mbuf *pkt, int offset,int size){
    struct transform_struc *transform = malloc(2 * __SIZEOF_POINTER__);
    if(transform){
        int actual = 0;
        void *objects[] = {0};
        do{
            transform->hdr = rte_pktmbuf_mtod_offset(pkt,struct transform_hdr *, offset);
            actual++;
            switch(transform->hdr->type){
                case ENCR:
                    break;
                case PRF:
                    break;
                case INTEG:
                    break;
                case D_H:
                    break;
                case ESN:
                    
                    break;
                default:
                    printf("Invalid Transform Type!");
                    break;
            }
            // printf("\n===================\nTransform %d\n===================",actual);
            // printf("\n| Type: %u",transform->hdr->type);
            // printf("\n| Type ID: %x",rte_be_to_cpu_16(transform->hdr->transform_ID));
            // printf("\n================================\n");
            if(transform->hdr->len != 8){
                //get attributes for transformation usually key length
                struct attr *attribute  = rte_pktmbuf_mtod_offset(pkt,struct attr *,offset + 8);
                transform->attribute = attribute;
            }
            if(actual > size){
                printf("Too many transformations!");
            }
            offset += rte_be_to_cpu_16(transform->hdr->len);
        }while(transform->hdr->nxt_payload != 0);
    }

}

/** deletes tunnel from authenticated tunnels once session ends
 * 
 * @param isakmp_hdr isakmp header containing initiator and responder spis to delete
 * @param ipv4_hdr IPV4 header containing respective ip addresses of client and host to remove
 * 
 */
void delete_tunnel(struct rte_isakmp_hdr *isakmp_hdr,struct rte_ipv4_hdr *ipv4_hdr){
    for(int i = 1;i <= tunnels->size; i++){
        struct tunnel *tunnel = tunnels->array[i];
        printf("%lx, %lx\n", rte_be_to_cpu_64(tunnel->host_spi), rte_be_to_cpu_64(tunnel->client_spi));
        if(check_ike_spi(isakmp_hdr,ipv4_hdr,tunnel) == 1){
            removeIndex(tunnels,i);
            break;
        }
    }
}

/** 
 * checks whether if ike information in tunnel matches isakmp header and ip address
 * @param isakmp_hdr isakmp header containing initiator and responder spis to check
 * @param ipv4_hdr IPV4 header containing respective ip addresses of client and host to check
 * @param tunnel tunnel to check
 * @returns 1 if information matches, 0 if otherwise
 */
int check_ike_spi(struct rte_isakmp_hdr *isakmp_hdr,struct rte_ipv4_hdr *ipv4_hdr,struct tunnel* tunnel){
    return (tunnel->client_spi == isakmp_hdr->initiator_spi 
                && tunnel->host_spi == isakmp_hdr->responder_spi) && ((tunnel->client_ip == ipv4_hdr->src_addr && tunnel->host_ip == ipv4_hdr->dst_addr) || 
                (tunnel->host_ip == ipv4_hdr->src_addr && tunnel->client_ip == ipv4_hdr->dst_addr)) ? 1 : 0;
}

/** 
 * checks whether if ike information in tunnel actually exists
 * @param isakmp_hdr isakmp header containing initiator and responder spis to check
 * @param ipv4_hdr IPV4 header containing respective ip addresses of client and host to check
 * @returns 1 if information matches, 0 if otherwise
 */
int check_if_tunnel_exists(struct rte_isakmp_hdr *isakmp_hdr,struct rte_ipv4_hdr *ipv4_hdr){
    for(int i = 1;i<=tunnels->size;i++){
        struct tunnel *tunnel = (struct tunnel *)tunnels->array[i];
        if(check_ike_spi(isakmp_hdr,ipv4_hdr,tunnel) == 1){
            return 1;
        }
    }
    return 0;
}

/** converts ip address into strings and place them in ip
 * @param ip_address ipv4 address to convert 
 * @param ip char pointer to store the converted string
 */
void get_ip_address_string(rte_be32_t ip_address,char *ip){
    int bit4 = ip_address >> 24 & 0xFF;
    int bit3 = ip_address >> 16 & 0xFF;
    int bit2 = ip_address >> 8 & 0xFF;
    int bit1 = ip_address & 0xFF;
    sprintf(ip,"%u.%u.%u.%u",bit1,bit2,bit3,bit4);
}   