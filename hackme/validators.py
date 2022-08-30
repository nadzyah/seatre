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
"""Functions that are used by other scripts in this module"""


import re
import binascii
from ipaddress import ip_address


def make_valid_mac_address(mac):
    """
    Check if MAC address is valid (format aa:aa:aa:aa:aa:aa)
    Then convert it to the next format: b"\xaa\xaa\xaa\xaa\xaa\xaa"
    """
    if mac is None:
        return
    if not re.match(
        "^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})|([0-9a-fA-F]{4}\\."
        "[0-9a-fA-F]{4}\\.[0-9a-fA-F]{4})$",
        mac,
    ):
        raise ValueError(
            f"MAC-address {mac} format is invalid. Please, write it "
            f"in aa:aa:aa:aa:aa:aa or aa-aa-aa-aa-aa-aa"
        )
    return binascii.unhexlify(mac.replace(":", "").replace("-", ""))


def validate_ip_address(ip):
    """Check if IPv4 address is valid"""
    try:
        ip_address(ip)
    except ValueError as exc:
        raise exc
    return ip
