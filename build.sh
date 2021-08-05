#reserve memory for packets
clear
echo 1024 | sudo tee /proc/sys/vm/nr_hugepages
if [ -d build ]
then
    # clean up to rebuild file if needed
    make clean
fi
make
./build/snart --vdev=net_pcap0,iface=ens33 -l 1 -n 4
