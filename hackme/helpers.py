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


import os
import re
import binascii
from textwrap import fill
from ipaddress import ip_address
from random import randint
import wikipedia


def make_valid_mac_address(mac):
    """
    Check if MAC address is valid (format aa:aa:aa:aa:aa:aa)
    Then convert it to the next format: b"\xaa\xaa\xaa\xaa\xaa\xaa"

    :mac: a string to be checked
    :return: None if mac is None or invalid, converted mac otherwise
    """
    if mac is None:
        return mac
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


def validate_ip_address(ip_addr):
    """
    Check if IPv4 address is valid

    :ip_addr: a string to be checked
    :return: None if ip_addr is None or invalid, ip_addr otherwise
    """
    if ip_addr is None:
        return ip_addr
    try:
        ip_address(ip_addr)
    except ValueError as exc:
        raise exc
    return ip_addr


def validate_port(port):
    """
    Check if port number is valid

    :port: an int to be checked
    :return: None if port is None or invalid, port otherwise
    """
    if port is None:
        return port
    port = int(port)
    if 0 < port < 65535:
        return port
    raise ValueError(f"Port number {port} is outside the range (1, 65535)")


def random_MAC():  # pylint: disable=C0103
    """
    Generate random MAC-address

    :return: MAC address in the aa:aa:aa:aa:aa:aa format
    """
    return "%02x:%02x:%02x:%02x:%02x:%02x" % (  # pylint: disable=C0209
        randint(0, 255),
        randint(0, 255),
        randint(0, 255),
        randint(0, 255),
        randint(0, 255),
        randint(0, 255),
    )


def random_IP():  # pylint: disable=C0103
    """
    Generate random IPv4-address

    :return: a string that represents IPv4 address
    """
    ip_addr = ".".join(map(str, (randint(0, 255) for _ in range(4))))
    return ip_addr


def random_port():
    """
    Generate random port

    :return: a random integer between 10000 and 65529
    """
    return randint(10000, 65530)


def progress_bar(it, total):  # pylint: disable=C0103
    """
    Print progress BAR as percentage of it out of total

    :it: the current number of items
    :total: the total number of items
    """
    fillwith = "#"
    dec = 2
    leng = 50
    percent = ("{0:." + str(dec) + "f}").format(100 * (it / float(total)))
    fill_length = int(leng * it // total)
    prog_bar = fillwith * fill_length + "-" * (leng - fill_length)
    print(f"\rProgress |{prog_bar}| {percent}% Complete", end="\r")


def get_description_from_wiki(name, width=None):
    """
    Return a pretty attack description from wikipedia

    :name: the name of an article
    :width: the text width
    """
    try:
        page = wikipedia.page(name)
    except wikipedia.exceptions.PageError as exc:
        return str(exc)
    if width is None:
        width = os.get_terminal_size().columns * 0.7
    result = fill(page.summary, width=width)
    result += "\n\n" + "Source: " + page.url
    return result
