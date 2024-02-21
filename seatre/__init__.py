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
"""The seatre package"""


from seatre.arp_spoofing import ARPSpoofer
from seatre.syn_flood import SYNFlooder
from seatre.udp_flood import UDPFlooder
from seatre.mac_flood import MACFlooder
from seatre.bpdu import BPDUPacket


__all__ = [
    "ARPSpoofer",
    "SYNFlooder",
    "UDPFlooder",
    "MACFlooder",
    "BPDUPacket",
]
