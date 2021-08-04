#include <stdint.h>
#include <inttypes.h>
#include <getopt.h>
#include <omp.h>

#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>
#include <rte_ring.h>
#include <rte_debug.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_icmp.h>
#include <unistd.h>


#include "include/ike.h"

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 1
#define ISAKMP_PORT 500
#define IPSEC_NAT_T_PORT 4500
#include <string.h>
#include <pthread.h>
#include <time.h>


/*
    ESP packet:
    |                  |               |            |             |        |
    |  Ethernet Header |  IPV4 Header  | UDP Header | ESP Header  |  Data  | ESP Trailer
    |                  |               |            |             |        |
    |                  |               |            |             |        |
*/

/**
 * @struct ISAKMP Test
 * @brief Test whether if incoming packet to/from NAT port is ISAKMP/IKE or ESP
 */
struct ISAKMP_TEST{
    /// 0 means IKE/ISAKMP else ESP
    uint32_t test_octet;
};
void * object[]= {0};

///Tolerance for sequence numbers in case they arrive in in correct order
uint32_t tolerance = 15;

static const int IPV4_OFFSET = sizeof(struct rte_ether_hdr);
static const int UDP_OFFSET = sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_ether_hdr);

static const int UDP_OFFSET_6 = sizeof(struct rte_ipv6_hdr) + sizeof(struct rte_ether_hdr);

static int rte_mbuf_dynfield_offset = -1;
static uint16_t count = 0;

int total_processed = 0;
int non_ipsec = 0;
int legit_pkts = 0;
int isakmp_pkts = 0;
int tampered_pkts = 0;
int malformed_pkts = 0;

/**
 * @struct ESP check struct
 * @brief Used to store spi and seq of a esp packet and check whether details correspond to the tunnel.
 */
struct check{
    /// Sequence number
    uint32_t seq;
    /// Security parameter index
    uint32_t spi;
};

void* count_packets(){
    printf("\rTotal packets processed: %d",total_processed);

    
}

/// Runs in the background to check for tunnel timeout for all established tunnels
void timeout(){
    while(true){
        current_time[0] = 0;
        get_current_time(current_time);
        for(int i = 1;i<=tunnels->size;i++){
            struct tunnel *tunnel = (struct tunnel *)tunnels->array[i];
            tunnel->timeout ++;
            int priority = LOG_INFO;
            if(tunnel->timeout == 40){
                char* client_ip[16] = {0};
                char* host_ip[16] = {0};
                get_ip_address_string(tunnel->client_ip,client_ip);
                get_ip_address_string(tunnel->host_ip,host_ip);
                char log[2048];
                if(tunnel->auth){
                    snprintf(log,2048,"%s;Session ended between %s and %s\n",current_time
                    ,client_ip, host_ip);
                }
                else{
                    snprintf(log,2048,"%s;IKE Authentication between %s and %s failed\n",current_time
                    ,client_ip, host_ip);
                    priority = LOG_NOTICE;
                }
                write_log(ipsec_log,log,priority);
                delete_tunnel(tunnel->initiator_spi,tunnel->responder_spi,tunnel->client_ip,tunnel->host_ip);
            }
        }
        sleep(1);
    }
}


/// Process packets
static uint16_t
read_data(uint16_t port __rte_unused, uint16_t qidx __rte_unused,
		struct rte_mbuf **pkts, uint16_t nb_pkts,
		uint16_t max_pkts __rte_unused, void *_ __rte_unused)
{
	unsigned i;
    get_current_time(current_time);
    
	for (i = 0; i < nb_pkts; i++){
        uint32_t x = rte_pktmbuf_data_len(pkts[i]); //get size of entire packet
        struct rte_mbuf *pkt = pkts[i];
        struct rte_ipv4_hdr *ipv4_hdr;
        struct rte_ether_hdr *ether_hdr;
        char log[2048] = {0};
        src_addr[0] = 0;
        dst_addr[0] = 0;
        bool malformed = false;
        if(sizeof(ether_hdr) < x){
            ether_hdr = rte_pktmbuf_mtod(pkt,struct rte_ether_hdr*);
            if(rte_be_to_cpu_16(ether_hdr->ether_type) == RTE_ETHER_TYPE_IPV4){
                if(IPV4_OFFSET + sizeof(struct rte_ipv4_hdr) <= x){
                    ipv4_hdr = rte_pktmbuf_mtod_offset(pkt,struct rte_ipv4_hdr *, IPV4_OFFSET); //get ipv4 header
                    /* check protocol (ICMP, UDP, TCP etc)
                        Due to UDP encapsulation, esp packet shld be within a udp packet with dst/src port 4500
                    */       
                    get_ip_address_string(ipv4_hdr->src_addr,src_addr);
                    get_ip_address_string(ipv4_hdr->dst_addr,dst_addr);

                    if(ipv4_hdr->next_proto_id == IPPROTO_UDP){
                        if(UDP_OFFSET + sizeof(struct rte_udp_hdr) <= x){
                            // printf("Protocol: UDP\n");
                            struct rte_udp_hdr *udp_hdr;
                            udp_hdr = rte_pktmbuf_mtod_offset(pkt,struct rte_udp_hdr *,UDP_OFFSET); //get udp header
                            //get src/dst ports and convert to big endian to log them
                            int dst_port = rte_cpu_to_be_16(udp_hdr->dst_port);
                            int src_port = rte_cpu_to_be_16(udp_hdr->src_port);
                            src_addr_int = ipv4_hdr->src_addr;
                            dst_addr_int = ipv4_hdr->dst_addr;
                            // printf("Src port: %u\n",dst_port);
                            // printf("Dst port: %u\n",src_port);
                            if(dst_port == IPSEC_NAT_T_PORT || src_port == IPSEC_NAT_T_PORT){
                                if(ESP_OFFSET + sizeof(struct ISAKMP_TEST) <= x){
                                    struct ISAKMP_TEST *test;
                                    test = rte_pktmbuf_mtod_offset(pkt,struct ISAKMP_TEST*,ESP_OFFSET);
                                    if(ISAKMP_OFFSET + sizeof(struct rte_isakmp_hdr) <= x || ESP_OFFSET + sizeof(struct rte_esp_hdr) <= x){
                                        if(test->test_octet == 0){
                                            struct rte_isakmp_hdr *isakmp_hdr;
                                            isakmp_hdr = rte_pktmbuf_mtod_offset(pkt,struct rte_isakmp_hdr*,ISAKMP_OFFSET);
                                            if(check_if_tunnel_exists(isakmp_hdr,ipv4_hdr)==1){
                                                int check = analyse_isakmp_payload(pkt,isakmp_hdr,first_payload_hdr_offset + 4,isakmp_hdr->nxt_payload);
                                                // print_isakmp_headers_info(isakmp_hdr);
                                                if(check == 1){
                                                    isakmp_pkts++;
                                                }
                                                else{
                                                    snprintf(log,2048,"%s;INVALID_ISAKMP_PACKET;%s;%s;%lx;%lx\n",current_time
                                                    ,src_addr, dst_addr, isakmp_hdr->initiator_spi,isakmp_hdr->responder_spi);
                                                    write_log(ipsec_log,log,LOG_WARNING);
                                                    tampered_pkts++;
                                                }
                                            }
                                            else{
                                                snprintf(log,2048,"%s;INVALID_ISAKMP_PACKET;%s;%s;%lx;%lx\n",current_time
                                                ,src_addr, dst_addr, isakmp_hdr->initiator_spi,isakmp_hdr->responder_spi);
                                                write_log(ipsec_log,log,LOG_WARNING);
                                                tampered_pkts++;
                                            }
                                        }
                                        else{
                                            //esp packet
                                            struct rte_esp_hdr *esp_header;
                                            esp_header = rte_pktmbuf_mtod_offset(pkt,struct rte_esp_hdr *,ESP_OFFSET); // get esp headers
                                            // log spi
                                            struct check tunnel_to_chk = {
                                                .seq = rte_be_to_cpu_32(esp_header->seq),
                                                .spi = rte_be_to_cpu_32(esp_header->spi)
                                            };
                                            
                                            // Lets check for new tunnels
                                            if (tunnels->size == 0){
                                                    snprintf(log,2048,"%s;UNAUTHORISED_ESP_PACKET;%s;%s;%x;%d\n",current_time
                                                    ,src_addr, dst_addr,tunnel_to_chk.spi,tunnel_to_chk.seq);

                                                    write_log(ipsec_log,log,LOG_WARNING);
                                                    tampered_pkts++;
                                            }else{
                                                struct tunnel* check;
                                                bool tunnel_exists = false;
                                                bool tampered = false;
                                                for (uint32_t i = 1; i <= tunnels->size; i++){
                                                    check = ((struct tunnel*) tunnels->array[i]);
                                                    if (check->client_ip == src_addr_int && check->host_ip == dst_addr_int){
                                                        if (check->client_spi == 0){
                                                            check->client_spi = esp_header->spi;
                                                            check->client_seq = rte_be_to_cpu_32(esp_header->seq);
                                                            if(check->host_spi != 0 ){
                                                                add_tunnel(check);
                                                            }
                                                            legit_pkts++;
                                                            tunnel_exists = true;
                                                        }
                                                        else if(check->client_spi == esp_header->spi){
                                                            int seq = rte_be_to_cpu_32(esp_header->seq);
                                                            if(check->client_seq <= (seq + tolerance) || check->client_seq >= (seq + tolerance)){
                                                                if(check->client_seq < seq){
                                                                    check->client_seq = seq;
                                                                }
                                                                legit_pkts++;
                                                                tunnel_exists = true;
                                                            }
                                                            else if(check->client_loaded){
                                                                check->client_seq = rte_be_to_cpu_32(esp_header->seq);
                                                                check->client_loaded = false;
                                                                legit_pkts++;
                                                                tunnel_exists = true;
                                                            }
                                                            else{
                                                                snprintf(log,2048,"%s;INVALID_SEQ_NO;%s;%s;%d;%d\n",current_time
                                                                ,src_addr, dst_addr,tunnel_to_chk.seq,check->client_seq);
                                                                
                                                                write_log(ipsec_log,log,LOG_WARNING);
                                                                tampered_pkts++;
                                                                tampered = true;
                                                                break;
                                                            }
                                                        }else{
                                                            snprintf(log,2048,"%s;INVALID_SPI;%s;%s;%x;%x\n",current_time
                                                            , src_addr, dst_addr,tunnel_to_chk.spi,check->initiator_spi);
                                                            
                                                            write_log(ipsec_log,log,LOG_WARNING);
                                                            tampered_pkts++;
                                                            tampered = true;
                                                            break;

                                                        }
                                                    }else if (check->host_ip == src_addr_int && check->client_ip == dst_addr_int){
                                                        if (check->host_spi == 0){
                                                            check->host_spi = esp_header->spi;
                                                            check->host_seq = rte_be_to_cpu_32(esp_header->seq);
                                                            if(check->client_spi != 0 ){
                                                                add_tunnel(check);
                                                            }
                                                            legit_pkts++;
                                                            tunnel_exists = true;
                                                            
                                                        }
                                                        else if(check->host_spi == esp_header->spi){
                                                            int seq = rte_be_to_cpu_32(esp_header->seq);
                                                            if(check->host_seq <= (seq + tolerance) || check->host_seq >= (seq - tolerance)){
                                                                if(check->client_seq < seq){
                                                                    check->host_seq = seq;
                                                                }
                                                                legit_pkts++;
                                                                tunnel_exists = true;
                                                            }
                                                            else if(check->host_loaded){
                                                                check->host_seq = rte_be_to_cpu_32(esp_header->seq);
                                                                check->host_loaded = false;
                                                                legit_pkts++;
                                                                tunnel_exists = true;
                                                            }
                                                            else{
                                                                snprintf(log,2048,"%s;INVALID_SEQ_NO;%s;%s;%d;%d\n",current_time
                                                                , src_addr, dst_addr,tunnel_to_chk.seq,check->host_seq);
                                                                
                                                                write_log(ipsec_log,log,LOG_WARNING);
                                                                tampered_pkts++;
                                                                tampered = true;
                                                                break;
                                                            }
                                                        }else {
                                                            snprintf(log,2048,"%s;INVALID_SPI;%s;%s;%x;%x\n",current_time
                                                            ,src_addr, dst_addr,tunnel_to_chk.spi,check->responder_spi);
                                                            
                                                            write_log(ipsec_log,log,LOG_WARNING);
                                                            tampered_pkts++;
                                                            tampered = true;
                                                            break;
                                                        }
                                                    }
                                                    if(tunnel_exists){
                                                        ((struct tunnel*) tunnels->array[i])->timeout = 0;
                                                        break;
                                                    }
                                                }
                                                if(!(tunnel_exists||tampered)){
                                                    snprintf(log,2048,"%s;UNAUTHORISED_ESP_PACKET;%s;%s;%x;%d\n",current_time
                                                    ,src_addr, dst_addr,tunnel_to_chk.spi,tunnel_to_chk.seq);
                                                    write_log(ipsec_log,log,LOG_WARNING);
                                                    tampered_pkts++;    
                                                }
                                            }
                                        }
                                    }
                                    else{
                                        malformed = true;
                                    }
                                }
                                else{
                                    malformed = true;
                                }
                            
                            }
                            else if(dst_port == ISAKMP_PORT || src_port == ISAKMP_PORT){
                                if(ESP_OFFSET + sizeof(struct rte_isakmp_hdr) <= x){
                                    struct rte_isakmp_hdr *isakmp_hdr;
                                    isakmp_hdr = rte_pktmbuf_mtod_offset(pkt,struct rte_isakmp_hdr*,ESP_OFFSET);
                                    // print_isakmp_headers_info(hdr);
                                    if(isakmp_hdr->exchange_type ==  IKE_SA_INIT){
                                        if(get_initiator_flag(isakmp_hdr) == 1){
                                            snprintf(log,2048,"%s;%s is trying to initiate IKE exchange with %s\n",current_time
                                            ,src_addr, dst_addr);
                                            write_log(ipsec_log,log,LOG_INFO);
                                        
                                        }
                                        else if(check_if_tunnel_exists(isakmp_hdr,ipv4_hdr)==0 && isakmp_hdr->responder_spi != (rte_be64_t)0){                                                                              
                                            //Only if server responds then tunnel should be considered legit
                                            struct tunnel new_tunnel;
                                            new_tunnel.host_ip = ipv4_hdr->src_addr;
                                            new_tunnel.client_ip = ipv4_hdr->dst_addr;

                                            new_tunnel.responder_spi = isakmp_hdr->responder_spi;
                                            new_tunnel.initiator_spi = isakmp_hdr->initiator_spi;
                                            new_tunnel.host_spi = 0;
                                            new_tunnel.client_spi = 0;

                                            new_tunnel.dpd = false;
                                            new_tunnel.dpd_count = 0;

                                            new_tunnel.client_seq = 0;
                                            new_tunnel.host_seq = 0;
                                            new_tunnel.timeout = 0;
                                            new_tunnel.auth = false;
                                            new_tunnel.client_loaded = false;
                                            new_tunnel.host_loaded = false;
                                            push(tunnels,&new_tunnel);
                                        }
                                        int check = analyse_isakmp_payload(pkt,isakmp_hdr,first_payload_hdr_offset + 4,isakmp_hdr->nxt_payload);
                                        // print_isakmp_headers_info(isakmp_hdr);
                                        if(check == 1){
                                            isakmp_pkts++;
                                        }
                                        else{
                                            snprintf(log,2048,"%s;INVALID_ISAKMP_PACKET;%s;%s;%lx;%lx\n",current_time
                                            ,src_addr, dst_addr, isakmp_hdr->initiator_spi,isakmp_hdr->responder_spi);
                                            write_log(ipsec_log,log,LOG_WARNING);
                                            tampered_pkts++;
                                        }

                                    }
                                    else{
                                        snprintf(log,2048,"%s;INVALID_ISAKMP_PACKET;%s;%s;%lx;%lx\n",current_time
                                        ,src_addr, dst_addr, isakmp_hdr->initiator_spi,isakmp_hdr->responder_spi);
                                        write_log(ipsec_log,log,LOG_WARNING);
                                        tampered_pkts++;
                                    }
                                    
                                }
                                else{
                                    malformed = true;
                                }
                            }
                            else{ 
                                //not esp packet
                                snprintf(log,2048,"%s;UDP;%s:%d->%s:%d\n",current_time
                                ,src_addr,src_port,dst_addr,dst_port);
                                write_log(main_log,log,LOG_WARNING);
                                non_ipsec++;
                                

                            }   
                                
                        }
                        else{
                            malformed = true;
                        }
                    }
                    else if(ipv4_hdr->next_proto_id == IPPROTO_TCP){
                        if(UDP_OFFSET + sizeof(struct rte_tcp_hdr) <= x){
                            //TCP packet
                            //TODO: should log protocol xD
                            struct rte_tcp_hdr* tcp_hdr;
                            tcp_hdr =  rte_pktmbuf_mtod_offset(pkt,struct rte_tcp_hdr*,UDP_OFFSET);
                            int src_port = rte_be_to_cpu_16(tcp_hdr->src_port);
                            int dst_port = rte_be_to_cpu_16(tcp_hdr->dst_port);
                            
                            snprintf(log,2048,"%s;TCP;%s:%d->%s:%d\n",current_time
                            ,src_addr,src_port,dst_addr,dst_port);
                            
                            write_log(main_log,log,LOG_WARNING);
                            non_ipsec++;
                        }

                        
                    }
                    else if(ipv4_hdr->next_proto_id == IPPROTO_ICMP){
                        //ICMP packet
                        if(UDP_OFFSET + sizeof(struct rte_icmp_hdr) <= x){
                            struct rte_icmp_hdr* icmp_hdr;
                            icmp_hdr = rte_pktmbuf_mtod_offset(pkt,struct rte_icmp_hdr*,UDP_OFFSET);
                            if(icmp_hdr->icmp_type == 0){
                                snprintf(log,2048,"%s;Ping response %s to %s\n",current_time,
                                src_addr,dst_addr);
                            }
                            else if(icmp_hdr->icmp_type == 8){
                                snprintf(log,2048,"%s;Ping request: %s to %s\n",current_time,src_addr,dst_addr);
                            }
                            else{
                                snprintf(log,2048,"%s;ICMP Packet: %s to %s\n",current_time,src_addr,dst_addr);
                            }
                            write_log(main_log,log,LOG_WARNING);
                            non_ipsec++;
                        }
                        else{
                            malformed = true;
                        }
                        
                    }
                    else{
                        non_ipsec++;
                    }
                }
                else{
                    malformed = true;
                }
            }
            else if(rte_be_to_cpu_16(ether_hdr->ether_type) == RTE_ETHER_TYPE_IPV6){
                if(IPV4_OFFSET + sizeof(struct rte_ipv6_hdr) <= x){
                    struct rte_ipv6_hdr *ipv6_hdr =rte_pktmbuf_mtod_offset(pkt,struct rte_ipv6_hdr*,IPV4_OFFSET);
                    get_ipv6_address_string(ipv6_hdr->src_addr,src_addr);
                    get_ipv6_address_string(ipv6_hdr->dst_addr,dst_addr);
                    if(ipv6_hdr->proto == IPPROTO_TCP){
                        if(UDP_OFFSET_6 + sizeof(struct rte_tcp_hdr) <= x){
                            //IPv6 TCP packet
                            struct rte_tcp_hdr* tcp_hdr;
                            
                            tcp_hdr =  rte_pktmbuf_mtod_offset(pkt,struct rte_tcp_hdr*,UDP_OFFSET_6);
                            int src_port = rte_be_to_cpu_16(tcp_hdr->src_port);
                            int dst_port = rte_be_to_cpu_16(tcp_hdr->dst_port);
                            
                            snprintf(log,2048,"%s;TCP;[%s]:%d->[%s]:%d\n",current_time
                            ,src_addr,src_port,dst_addr,dst_port);
                            printf("%s",log);
                            write_log(main_log,log,LOG_WARNING);
                        }
                    }
                     if(ipv6_hdr->proto == IPPROTO_UDP){
                        if(UDP_OFFSET_6 + sizeof(struct rte_tcp_hdr) <= x){
                            //IPv6 TCP packet
                            struct rte_udp_hdr* udp_hdr;
                            udp_hdr =  rte_pktmbuf_mtod_offset(pkt,struct rte_udp_hdr*,UDP_OFFSET_6);
                            int src_port = rte_be_to_cpu_16(udp_hdr->src_port);
                            int dst_port = rte_be_to_cpu_16(udp_hdr->dst_port);
                            
                            snprintf(log,2048,"%s;UDP;[%s]:%d->[%s]:%d\n",current_time
                            ,src_addr,src_port,dst_addr,dst_port);
                            
                            write_log(main_log,log,LOG_WARNING);
                        }
                    }
                    else if(ipv6_hdr->proto == IPPROTO_ICMPV6){
                        //ICMP packet
                        if(UDP_OFFSET + sizeof(struct rte_icmp_hdr) <= x){
                            struct rte_icmp_hdr* icmp_hdr;
                            icmp_hdr = rte_pktmbuf_mtod_offset(pkt,struct rte_icmp_hdr*,UDP_OFFSET_6);
                            if(icmp_hdr->icmp_type == 0){
                                snprintf(log,2048,"%s;Ping response %s to %s\n",current_time,
                                src_addr,dst_addr);
                            }
                            else if(icmp_hdr->icmp_type == 8){
                                snprintf(log,2048,"%s;Ping request: %s to %s\n",current_time,src_addr,dst_addr);
                            }
                            else{
                                snprintf(log,2048,"%s;ICMP Packet: %s to %s\n",current_time,src_addr,dst_addr);
                            }
                            write_log(main_log,log,LOG_WARNING);
                        }
                        else{
                            malformed = true;
                        }
                        
                    }
                    non_ipsec ++;
                }
                else{
                    malformed = true;
                }
            }
            else{
                non_ipsec ++;
            }
        }
        else{
            malformed = true;
        }
        if(malformed){
            if(src_addr[0] != "\0" && dst_addr[0] != "\0"){
                
                snprintf(log,2048,"%s;MALFORMED_PACKET;%s;%s\n",current_time,src_addr,dst_addr);
            }
            else{
                 snprintf(log,2048,"%s;MALFORMED_PACKET\n",current_time);
            }
            write_log(main_log,log,LOG_WARNING);
            malformed ++;
        }
        total_processed++;
        if(total_processed % 10 == 0) {
            printf("\e[1;1H\e[2J");
            printf("================================\n          Tunnels\n================================\n");
            for (uint32_t i = 1; i <= tunnels->size; i++){
                struct tunnel* check = ((struct tunnel*) tunnels->array[i]);
                printf("--------------------------------\n| tunnel %d\n",i);
                int bit4 = check->client_ip >> 24 & 0xFF;
                int bit3 = check->client_ip >> 16 & 0xFF;
                int bit2 = check->client_ip >> 8 & 0xFF;
                int bit1 = check->client_ip & 0xFF;
                printf("| Client: %u.%u.%u.%u\n",bit1,bit2,bit3,bit4);
                bit4 = check->host_ip >> 24 & 0xFF;
                bit3 = check->host_ip >> 16 & 0xFF;
                bit2 = check->host_ip >> 8 & 0xFF;
                bit1 = check->host_ip & 0xFF;
                printf("| Host: %u.%u.%u.%u\n",bit1,bit2,bit3,bit4);
            }
            printf("================================");
            printf("\n| Non IPSec packets: %d", non_ipsec);
            printf("\n| Tampered IPSec packets: %d",tampered_pkts);
            printf("\n| Legitimate IPSec packets: %d",legit_pkts + isakmp_pkts);
            printf("\n| Malformed packets: %d",malformed);
            printf("\n| Total packets processed: %d\n",total_processed);
            printf("================================\n");
            int unaccounted = total_processed - non_ipsec - tampered_pkts - legit_pkts - isakmp_pkts - malformed;
            if( unaccounted == 0){
                printf("| All traffic accounted for\n");
            }else{
                printf("| %d packets unaccounted for. \n| Please check network logs.\n", unaccounted);
            }
            printf("================================\n");
        }
    }
       
	return nb_pkts;
}

/// Init ports used to capture packets
int port_init(uint16_t port,struct rte_mempool *mbufpool){
    struct rte_eth_conf port_conf = {
        .rxmode = {
            .max_rx_pkt_len = RTE_ETHER_MAX_LEN // max packet size
        }
    };
    const uint16_t rx_rings = 1, tx_rings = 1;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_rxconf rxconf;
    struct rte_eth_txconf txconf;

    if(!rte_eth_dev_is_valid_port(port)) return -1;

    retval = rte_eth_dev_info_get(port,&dev_info);

    if(retval !=0){
        printf("Failed to retrieve information of device %u: Error: %s\n",port,strerror(-retval));
        return retval;
    }

    if(dev_info.rx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE){
        port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;
    }

    retval = rte_eth_dev_configure(port,rx_rings,tx_rings,&port_conf);
    if(retval != 0){
        return retval;
    }

    for(q = 0; q<rx_rings;q++){
        retval = rte_eth_rx_queue_setup(port,q,nb_rxd,rte_eth_dev_socket_id(port),&rxconf,mbufpool);
        if(retval !=0){
            return retval;
        }
    }

    retval = rte_eth_dev_start(port);
    if(retval !=0){
        return retval;
    }
    struct rte_ether_addr addr;
    
    retval = rte_eth_macaddr_get(port,&addr);
    if(retval !=0){
        printf("Failed to get mac address of port %u\n",port);
    }

    printf("Port %u MAC: %02x %02x %02x %02x %02x %02x\n",port,
    addr.addr_bytes[0],addr.addr_bytes[1],addr.addr_bytes[2],addr.addr_bytes[3],addr.addr_bytes[4],addr.addr_bytes[5]);
    
    retval = rte_eth_promiscuous_enable(port);

    if(retval != 0){
        return retval;
    }
    rte_eth_add_rx_callback(port,0,read_data,NULL);
    return 0;
}

/// Function to run for each port to capture packets and process them
static __rte_noreturn void 
lcore_main(void){
    uint16_t port;
    for(;;){
        RTE_ETH_FOREACH_DEV(port){
            struct rte_mbuf *bufs[BURST_SIZE];
            const uint16_t nb_rx = rte_eth_rx_burst(port,0,bufs,BURST_SIZE);
            if (unlikely(nb_rx == 0)){
                continue;
            }
			const uint16_t nb_tx = 0;
			if (unlikely(nb_tx < nb_rx)) {
				uint16_t buf;
				for (buf = nb_tx; buf < nb_rx; buf++)
					rte_pktmbuf_free(bufs[buf]);
			}
        }
    }
}

int main(int argc, char **argv){
    struct rte_mempool *mbuf_pool;
    uint16_t nb_ports;
    uint16_t portid;
    
    static const struct rte_mbuf_dynfield params = {
        .name = "testing",
        .size = sizeof(uint64_t),
        .align = __alignof__(uint64_t)
    };

    int ret = rte_eal_init(argc,argv);

    if(ret < 0){
        rte_exit(EXIT_FAILURE,"Error with EAL initialisation\n");
    }

    //count number of avaliable ports
    nb_ports = rte_eth_dev_count_avail();

    if(nb_ports < 1){
        rte_exit(EXIT_FAILURE,"No ports are available!\n");        
    }

    //create mbuf_pool
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",NUM_MBUFS * nb_ports,MBUF_CACHE_SIZE,
    0,RTE_MBUF_DEFAULT_BUF_SIZE,rte_socket_id());

    if(mbuf_pool == NULL){
        rte_exit(EXIT_FAILURE,"Cannot create mbuf pool\n");
    }
    
    //register dynamic field
    rte_mbuf_dynfield_offset = rte_mbuf_dynfield_register(&params);

    if(rte_mbuf_dynfield_offset < 0){
        rte_exit(EXIT_FAILURE,"Cannot register mbuf field\n");
    }

    //init all ports
    RTE_ETH_FOREACH_DEV(portid){
        if(port_init(portid,mbuf_pool) !=0){
            rte_exit(EXIT_FAILURE,"Failed to initialise port %u\n",portid);
        }
    }
    tunnels = malloc(sizeof(struct Array));
    printf("\n\n\n\n\n\n\n\n\n\n\n\n=====================\nNow monitoring...\n=====================\n\n");
    if (tunnels) {
        initArray(tunnels,0,object,false,sizeof(struct tunnel));
        pthread_t thread;
        pthread_create(&thread,NULL,timeout,NULL);
        load_tunnel();
        lcore_main();
        rte_eal_cleanup();
    }

    return 0;
}   