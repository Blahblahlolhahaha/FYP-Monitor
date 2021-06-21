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



#include "include/ike.h"

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 1
#define ISAKMP_PORT 500
#define IPSEC_NAT_T_PORT 4500
#include <string.h>



/*
    ESP packet:
    |                  |               |            |             |        |
    |  Ethernet Header |  IPV4 Header  | UDP Header | ESP Header  |  Data  | ESP Trailer
    |                  |               |            |             |        |
    |                  |               |            |             |        |
*/

struct ISAKMP_TEST{
    uint32_t test_octet;
};
void * object[]= {0};

//Adjust sequence number tolerance
uint32_t tolerance = 2;

static const int IPV4_OFFSET = sizeof(struct rte_ether_hdr);
static const int UDP_OFFSET = sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_ether_hdr);

static int rte_mbuf_dynfield_offset = -1;
static uint16_t count = 0;
int total_processed = 0;
int non_ipsec = 0;
int legit_pkts = 0;
int isakmp_pkts = 0;
int tampered_pkts = 0;

struct check{
    int src;
    int dst;
    uint32_t seq;
    uint32_t spi;
};

void* count_packets(){
    printf("\rTotal packets processed: %d",total_processed);

    
}

static uint16_t
read_data(uint16_t port __rte_unused, uint16_t qidx __rte_unused,
		struct rte_mbuf **pkts, uint16_t nb_pkts,
		uint16_t max_pkts __rte_unused, void *_ __rte_unused)
{
	unsigned i;
	uint64_t now = rte_rdtsc();
    
    
	for (i = 0; i < nb_pkts; i++){
        uint32_t x = rte_pktmbuf_data_len(pkts[i]); //get size of entire packet
        struct rte_mbuf *pkt = pkts[i];
        struct rte_ipv4_hdr *hdr;
        hdr = rte_pktmbuf_mtod_offset(pkt,struct rte_ipv4_hdr *, IPV4_OFFSET); //get ipv4 header
        // printf("Packet %u:\n",count);
        // printf("Size %u\n",x);

        //get src and dst ip addresses in x.x.x.x form
        int src_bit4 = hdr->src_addr >> 24 & 0xFF;
        int src_bit3 = hdr->src_addr >> 16 & 0xFF;
        int src_bit2 = hdr->src_addr >> 8 & 0xFF;
        int src_bit1 = hdr->src_addr & 0xFF;
        
        int dst_bit4 = hdr->dst_addr >> 24 & 0xFF;
        int dst_bit3 = hdr->dst_addr >> 16 & 0xFF;
        int dst_bit2 = hdr->dst_addr >> 8 & 0xFF;
        int dst_bit1 = hdr->dst_addr & 0xFF;
        // printf("Src IP: %u.%u.%u.%u\n",src_bit1,src_bit2,src_bit3,src_bit4);
        // printf("Dst IP: %u.%u.%u.%u\n",dst_bit1,dst_bit2,dst_bit3,dst_bit4);

        /* check protocol (ICMP, UDP, TCP etc)
            Due to UDP encapsulation, esp packet shld be within a udp packet with dst/src port 4500
        */       
        int counted = 0;
        if(hdr->next_proto_id == IPPROTO_UDP){
            // printf("Protocol: UDP\n");
            struct rte_ipv4_hdr *inner_header;
            struct rte_udp_hdr *udp_hdr;

            udp_hdr = rte_pktmbuf_mtod_offset(pkt,struct rte_udp_hdr *,UDP_OFFSET); //get udp header
            //get src/dst ports and convert to big endian to log them
            int dst_port = rte_cpu_to_be_16(udp_hdr->dst_port);
            int src_port = rte_cpu_to_be_16(udp_hdr->src_port);
            int src_addr_int = rte_cpu_to_be_32(hdr->src_addr);
            int dst_addr_int = rte_cpu_to_be_32(hdr->dst_addr);
            // printf("Src port: %u\n",dst_port);
            // printf("Dst port: %u\n",src_port);

            if(dst_port == IPSEC_NAT_T_PORT || src_port == IPSEC_NAT_T_PORT){
                struct ISAKMP_TEST *test;
                test = rte_pktmbuf_mtod_offset(pkt,struct ISAKMP_TEST*,ESP_OFFSET);
                if(test->test_octet == 0){
                    struct rte_isakmp_hdr *isakmp_hdr;
                    isakmp_hdr = rte_pktmbuf_mtod_offset(pkt,struct rte_isakmp_hdr*,ISAKMP_OFFSET);
                    int check = analyse_isakmp_payload(pkt,isakmp_hdr,hdr,first_payload_hdr_offset + 4,isakmp_hdr->nxt_payload);
                    // print_isakmp_headers_info(isakmp_hdr);
                    if(check == 1){
                        isakmp_pkts++;
                    }
                    else{
                        tampered_pkts++;
                        printf("no ike sad");
                        exit(0);
                    }
                    counted++;
                }
                else{
                    //esp packet
                    struct rte_esp_hdr *esp_header;
                    esp_header = rte_pktmbuf_mtod_offset(pkt,struct rte_esp_hdr *,ESP_OFFSET); // get esp headers
                    // log spi
                    printf("SPI: %04x\n",rte_be_to_cpu_32(esp_header->spi));
                    printf("Seq: %u\n",rte_be_to_cpu_32(esp_header->seq));
                    printf("yayyyyyy\n\n");
                    struct check tunnel_to_chk = {
                        .src = src_addr_int,
                        .dst = dst_addr_int,
                        .seq = rte_be_to_cpu_32(esp_header->seq),
                        .spi = rte_be_to_cpu_32(esp_header->spi)
                    };
                    bool tunnel_exists = false;
                    // Lets check for new tunnels
                    if (tunnels->size == 0){
                            printf("\nUnauthorized packet detected");
                            tampered_pkts++;
                            printf("packet without tunnel");
                            exit(0);
                    }else{
                        for (uint32_t i = 1; i <= tunnels->size; i++){
                            struct tunnel* check = ((struct tunnel*) tunnels->array[i]);

                            if (rte_be_to_cpu_32(check->client_ip) == src_addr_int && rte_be_to_cpu_32(check->host_ip) == dst_addr_int){
                                if (!check->client_esp_spi){
                                    struct tunnel updated = *check;
                                    updated.client_esp_spi = esp_header->spi;
                                    tunnels->array[i] = (void *)(&updated);
                                    legit_pkts++;
                                    tunnel_exists = true;
                                }
                                else if(check->client_esp_spi == esp_header->spi){
                                    if(check->client_seq + 1 == rte_be_to_cpu_32(esp_header->seq)){
                                        check->client_seq = rte_be_to_cpu_32(esp_header->seq);
                                        legit_pkts++;
                                        tunnel_exists = true;
                                    }else{
                                        tampered_pkts++;
                                        printf("sequence nvr match");
                                        exit(0);
                                        
                                    }
                                }else{
                                    tampered_pkts++;
                                    printf("Host SPI : %x\n",check->host_esp_spi);
                                    printf("Client ESP SPI : %x\n",check->client_esp_spi);
                                    printf("Client SPI : %x\n",esp_header->spi);
                                    tampered_pkts++;
                                    printf("spi nvr match");
exit(0);
                                }
                            }else if (rte_be_to_cpu_32(check->host_ip) == src_addr_int && rte_be_to_cpu_32(check->client_ip) == dst_addr_int){
                                if (!check->host_esp_spi){
                                    struct tunnel updated = *check;
                                    updated.host_esp_spi = esp_header->spi;
                                    tunnels->array[i] = (void *)(&updated);
                                    legit_pkts++;
                                    tunnel_exists = true;
                                }
                                else if(check->host_esp_spi == esp_header->spi){
                                    if(check->host_seq + 1 == rte_be_to_cpu_32(esp_header->seq)){
                                        check->host_seq = rte_be_to_cpu_32(esp_header->seq);
                                        legit_pkts++;
                                        tunnel_exists = true;
                                    }else{
                                        tampered_pkts++;
                                        printf("sequence nvr match");
exit(0);
                                    }
                                }else {
                                    printf("Host SPI : %x\n",check->host_esp_spi);
                                    printf("Client ESP SPI : %x\n",check->client_esp_spi);
                                    printf("Client SPI : %x\n",esp_header->spi);
                                    tampered_pkts++;
                                    printf("spi nvr match");
exit(0);
                                }
                            }
                        }
                        if (!tunnel_exists){
                            tampered_pkts++;
                            printf("Tunnel didnt exist");
                            exit(0);
                        }
                    }
                }
               
            }
            else if(dst_port == ISAKMP_PORT || src_port == ISAKMP_PORT){
                struct rte_isakmp_hdr *isakmp_hdr;
                isakmp_hdr = rte_pktmbuf_mtod_offset(pkt,struct rte_isakmp_hdr*,ESP_OFFSET);
                // print_isakmp_headers_info(hdr);
                if(isakmp_hdr->exchange_type ==  IKE_SA_INIT){
                    if(get_initiator_flag(isakmp_hdr) == 1){

                        char* src_ip[15];
                        char* dst_ip[15];
                        if(src_ip && dst_ip){
                            get_ip_address_string(hdr->src_addr,src_ip);
                            get_ip_address_string(hdr->dst_addr,dst_ip);
                            printf("%s is trying to initiate IKE exchange with %s\n", src_ip, dst_ip);

                        }
                    }
                    else{
                        analyse_isakmp_payload(pkt,isakmp_hdr,hdr,first_payload_hdr_offset,isakmp_hdr->nxt_payload);
                    }
                    
                    
                }
                isakmp_pkts++;
                counted++;
            }
            else{ 
               //not esp packet
                // printf("\n\n===================\nNon IPSec UDP packet detected\n===================");
                // printf("\n| packet's source ip: %u.%u.%u.%u",src_bit1,src_bit2,src_bit3,src_bit4);
                // printf("\n| packet's destination ip: %u.%u.%u.%u\n",dst_bit1,dst_bit2,dst_bit3,dst_bit4);
                // printf("\n===================\n\n");
                non_ipsec++;
                counted++;

            }   
        }
        else{
            //TODO: should log protocol xD
            // printf("Not UDP\n\n");
            non_ipsec++;
            counted++;
        }
        total_processed++;
        if(total_processed % 10 == 0) {
            printf("\e[1;1H\e[2J");
            printf("================================\n          Tunnels\n================================\n");
            for (uint32_t i = 1; i <= tunnels->size; i++){
                struct tunnel* check = ((struct tunnel*) tunnels->array[i]);
                //get src and dst ip addresses in x.x.x.x form
                int srcip_bit4 = check->client_ip >> 24 & 0xFF;
                int srcip_bit3 = check->client_ip >> 16 & 0xFF;
                int srcip_bit2 = check->client_ip >> 8 & 0xFF;
                int srcip_bit1 = check->client_ip & 0xFF;
                
                int dstip_bit4 = check->host_ip >> 24 & 0xFF;
                int dstip_bit3 = check->host_ip >> 16 & 0xFF;
                int dstip_bit2 = check->host_ip >> 8 & 0xFF;
                int dstip_bit1 = check->host_ip & 0xFF;


                char* src_ip[15];
                char* dst_ip[15];
                if(src_ip && dst_ip){
                    printf("--------------------------------\n| tunnel %d\n",i);
                    get_ip_address_string(check->client_ip,src_ip);
                    get_ip_address_string(check->host_ip,dst_ip);
                    printf("| Client: %s\n",src_ip);
                    printf("| Host: %s\n",dst_ip);
                    
                }
            }
            printf("================================");
            printf("\n| Non IPSec packets: %d", non_ipsec);
            printf("\n| Tampered IPSec packets: %d",tampered_pkts);
            printf("\n| Legitimate IPSec packets: %d",legit_pkts + isakmp_pkts);
            printf("\n| Total packets processed: %d\n",total_processed);
            printf("================================\n");
            if(total_processed - non_ipsec - tampered_pkts - legit_pkts - isakmp_pkts == 0){
                printf("| All traffic accounted for\n");
            }else{
                printf("| %d packets unaccounted for. \n| Please check network logs.\n", total_processed - non_ipsec - tampered_pkts - legit_pkts - isakmp_pkts);
            }
            printf("================================\n");
        }

    }
       
	return nb_pkts;
}

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
        lcore_main();
        rte_eal_cleanup();
    }

    


    return 0;
}   