# Design-and-build-of-tamper-evident-cloud-office-services

## How to use:
```
sudo ./build.sh
```


## Explanation
Some explanation in code but in general:

NAT-T used by IPsec uses UDP port 4500, IKE_SA_INIT uses UDP port 500

Using next payload number and exchange type in IKE header, can identify data stored within IKE packet


## TODO:
Log SPI pair for each remote ip client sad :(
Log other ip protocols like tcp/icmp

## Whats Done:
* Capturing of IKE headers and ESP headers.
* Finding out payload type found within IKE headers using the next payload number.
* Storing tunnels based on ip, spis
* Can identify successful/unsuccessful ike exchanges
* Can identify ike session ending
* Can identify dead pear(theorectical, havent test yet)

## Whats Not Done:
* Use SPI and sequence numebers to find out sus packets

* Flagging tcp packets and udp thats not port 500 and 4500
* Proper logging to file