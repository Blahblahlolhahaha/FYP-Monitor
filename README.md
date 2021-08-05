# Design-and-build-of-tamper-evident-cloud-office-services
## NO LONGER ACTIVELY MAINTAINED  
  
![piggu!](https://i.imgur.com/F5vlk0u.png)

Secure Network Anomaly Real Time detection (SNART) is a network anomaly detection  
system specifically targetted at networks which enforce IPsec VPN throughout the  
network. It counts and logs any packets which do not fall within a valid IKEv2 tunnel  
with valid packet properties.


## How to use:
```
sudo ./build.sh
```


## Explanation
Some explanation in code but in general:

NAT-T used by IPsec uses UDP port 4500, IKE_SA_INIT uses UDP port 500

Using next payload number and exchange type in IKE header, can identify data stored within IKE packet


## TODO:
* Fix bug where timeout will not remove tunnels

## Whats Done:
* Capturing of IKE headers and ESP headers.
* Finding out payload type found within IKE headers using the next payload number.
* Storing tunnels based on ip, spis
* Can identify successful/unsuccessful ike exchanges
* Can identify ike session ending
* Can identify dead pear(theorectical, havent test yet)
* Use SPI and sequence numebers to find out sus packets
* Flagging tcp packets and udp thats not port 500 and 4500
* Proper logging to file
* Saving tunnels such that if program crashes or terminated, can resume with tunnels that exists before termination

## Limitations
* Tunnels will only be saved when initiator,responder spi from the isakmp header, client and host esp spi and client and host address are collected

## Whats Not Done:
