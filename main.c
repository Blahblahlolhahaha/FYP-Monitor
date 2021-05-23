#include <stdint.h>
#include <inttypes.h>
#include <getopt.h>
#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>
#include <rte_ring.h>
#include <rte_debug.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>

#include <rte_ethdev.h>
#include <rte_ether.h>
#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

static int rte_mbuf_dynfield_offset = -1;
static uint16_t count = 0;
static uint16_t
read_data(uint16_t port __rte_unused, uint16_t qidx __rte_unused,
		struct rte_mbuf **pkts, uint16_t nb_pkts,
		uint16_t max_pkts __rte_unused, void *_ __rte_unused)
{
	unsigned i;
	uint64_t now = rte_rdtsc();

	for (i = 0; i < nb_pkts; i++){
        void *data;
        uint32_t x = rte_pktmbuf_data_len(pkts[i]);
        struct rte_ipv4_hdr *hdr;
        hdr = rte_pktmbuf_mtod_offset(pkts[i],struct rte_ipv4_hdr *,sizeof(struct rte_ether_hdr));
        uint8_t* sad = (uint8_t*) data;
        count++;
        printf("Packet %u:\n",count);
        printf("Size %u\n",x);
        int src_bit4 = hdr->src_addr >> 24 & 0xFF;
        int src_bit3 = hdr->src_addr >> 16 & 0xFF;
        int src_bit2 = hdr->src_addr >> 8 & 0xFF;
        int src_bit1 = hdr->src_addr & 0xFF;
        
        int dst_bit4 = hdr->dst_addr >> 24 & 0xFF;
        int dst_bit3 = hdr->dst_addr >> 16 & 0xFF;
        int dst_bit2 = hdr->dst_addr >> 8 & 0xFF;
        int dst_bit1 = hdr->dst_addr & 0xFF;
        printf("Src IP: %u.%u.%u.%u\n",src_bit1,src_bit2,src_bit3,src_bit4);
        printf("Dst IP: %u.%u.%u.%u\n",dst_bit1,dst_bit2,dst_bit3,dst_bit4);
        if(hdr->next_proto_id == IPPROTO_ICMP){
            printf("Protocol: ICMP\n\n");
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

    printf("sad\n");
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

    lcore_main();
    rte_eal_cleanup();

    return 0;
}   
