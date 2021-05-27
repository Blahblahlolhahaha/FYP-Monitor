# Design-and-build-of-tamper-evident-cloud-office-services

## How to use:
```
sudo ./build.sh
```


## Explanation
Some explanation in code but in general:

NAT-T used by IPsec uses UDP port 4500

Soooooooo for now, can just flag out any traffic thats not using udp port 4500 


## TODO:
Log SPI pair for each remote ip client sad :(
Log other ip protocols like tcp/icmp

## Some plans:
Use SPI and sequence numebers to find out sus packets

Flow: ISAKMP btw clients and fw every 2mins? Other comms using ESP

Store SPI pairs/sequence number somewhr (memory,file,sql db whatever)
* Can track out dead clients by tracking time (idk abt this one)
* If got SPI that doesnt match any records, flag it
* If sequence number not in sequence, flag it
