#reserve memory for packets
clear
echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages // reserve memory 
if [ -d build ]
then
    # clean up to rebuild file if needed
    make clean
fi
make
./build/rxtx_callbacks --vdev=net_pcap0,iface=ens33 -l 1 -n 4
