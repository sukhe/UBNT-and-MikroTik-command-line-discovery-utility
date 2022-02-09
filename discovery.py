#!/usr/bin/env python
""" Discovery UBNT and MikroTik devices is local network """

import sys
import logging

import json
import argparse
import csv
import time

from concurrent.futures.thread import ThreadPoolExecutor

import scapy.all
from scapy.config import conf
conf.use_pcap = True

from netifaces import ifaddresses, AF_LINK, AF_INET

from discovery_lib import *
import mt_lib as mt
import ubnt_lib as ubnt

# Disable annoying warning messages from Scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Define type aliases
PacketList = scapy.plist.PacketList
Ether = scapy.layers.l2.Ether
IP = scapy.layers.inet.IP
UDP = scapy.layers.inet.UDP


organization_specific = {
    # 00:80:C2 'IEEE 802.1'
    "ieee802.1": {
        0x01: ["Port VLAN Identifier", mt.int_without_first_byte],
        0x03: ["VLAN Name", mt.vlanname],
        0x04: ["Protocol Identity", mt.prot_iden],
    },
    # 00:12:0F 'IEEE 802.3'
    "ieee802.3": {
        0x01: ["MAC/PHY Configuration/Status", mt.mac_phy],
        0x02: ["Power Via MDI", mt.mdi_power],
        0x03: ["Link Aggregation", mt.aggregation],
        0x04: ["Maximum Frame Size", mt.int_without_first_byte],
    },
    # 00:12:bb 'TR-41'
    "tr-41": {0x01: ["Media Capabilities", mt.media_capabilities]},
}


def org_spec(x: bytes) -> dict:
    """ Decode organization specific fields

    Args:
        x: source bytestring

    Returns:
        Organization specific information
    """
    if x[:3] == b"\x00\x80\xC2":
        field_type: int = x[3]
        field_name: str = organization_specific["ieee802.1"][field_type][0]
        field_func: callable = organization_specific["ieee802.1"][field_type][1]
        value = field_func(x[3:])
    elif x[:3] == b"\x00\x12\x0F":
        field_type: int = x[3]
        field_name: str = organization_specific["ieee802.3"][field_type][0]
        field_func: callable = organization_specific["ieee802.3"][field_type][1]
        value = field_func(x[3:])
    elif x[:3] == b"\x00\x12\xBB":
        field_type: int = x[3]
        field_name: str = organization_specific["tr-41"][field_type][0]
        field_func: callable = organization_specific["tr-41"][field_type][1]
        value = field_func(x[3:])
    else:
        field_name = "Unknown organization " + x[:3].hex() + ", field type " + str(x[3])
        value = x[4:]
    return {field_name: value}


decode_schema = {
    "cdp": {
        0x0001: ["Device ID", to_str],
        0x0002: ["Addresses", mt.addresses],
        0x0003: ["Port ID", to_str],
        0x0004: ["Capabilities", mt.cdp_capabilities],
        0x0005: ["Software Version", to_str],
        0x0006: ["Platform", to_str],
    },
    "mndp": {
        0x0001: ["MAC-Address", mac_str_from6bytes],
        0x0005: ["Identity", to_str],
        0x0007: ["Version", to_str],
        0x0008: ["Platform", to_str],
        0x000A: ["Uptime", mt.mt_uptime],
        0x000B: ["Software-ID", to_str],
        0x000C: ["Board", to_str],
        0x000E: ["Unpack", to_hex],
        0x000F: ["IPv6-Address", ip6_str_from16bytes],
        0x0010: ["Interface name", to_str],
        0x0011: ["IPv4-Address", ip_str_from4bytes],
    },
    "lldp": {
        0x01: ["Chassis Subtype", mt.chassis_subtype],
        0x02: ["Port Subtype", mt.port_subtype],
        0x03: ["Time to Live", to_int],
        0x04: ["Port Description", to_str],
        0x05: ["System Name", to_str],
        0x06: ["System Description", to_str],
        0x07: ["Capabilities", mt.lldp_capabilities],
        0x08: ["Management Address", mt.mgmt_address],
        0x7F: ["Organization Specific", org_spec],
    },
    "ubnt": {
        0x01: ["macaddr", mac_str_from6bytes],
        0x02: ["ipinfo", ubnt.ipinfo],
        0x03: ["firmware", to_str],
        0x0A: ["uptime", uptime_str_from4bytes],
        0x0B: ["hostname", to_str],
        0x0C: ["platform", to_str],
        0x0D: ["essid", to_str],
        0x0E: ["wmode", ubnt.wmode],
        0x10: ["sysid", to_hex],
        0x14: ["model", to_str],
    }
}


def decoder(field_type: int, value: bytes, schema: str) -> dict:
    """ Decode type-length-value (TLV) fields using templates

    Args:
        field_type: field type ID
        value: value, stored in field
        schema: decoding template

    Returns:
        dict: key-value pair extracted from this field
    """
    try:
        field_name: str = decode_schema[schema][field_type][0]
        field_func: callable = decode_schema[schema][field_type][1]
        val = field_func(value)
    except KeyError:
        field_name = "Unknown_type"
        val = f"Field type: {field_type} Value: {value}"
    return {field_name: val}


def process_all_fields(packet: bytes, proto: str) -> dict:
    """ Process all TLV fields in packet

    Args:
        packet:  payload of packet
        proto: protocol

    Returns:
        Decoded key-value pairs
    """
    processed_data: dict = {}
    unprocessed_data: bytes = packet
    while len(unprocessed_data) > 0:
        field_type, value, unprocessed_data = tlv_dissect(unprocessed_data, proto)
        decoded_data: dict = decoder(field_type, value, proto)
        if proto == "lldp":
            if (field_type == 127
                and ("Organization Specific" in processed_data)
                and ("Organization Specific" in decoded_data)):
                processed_data["Organization Specific"].update(decoded_data["Organization Specific"])
            elif field_type != 0:
                processed_data.update(decoded_data)
        else:
            processed_data.update(decoded_data)
    return processed_data


def parsing(packets: PacketList, arg: dict) -> list:
    """ Split all gathered information into packets from individual devices
        And get data from all of them

    Args:
        packets: all massive of captured information
        arg: configuration parameters

    Returns:
        Parsed packets
    """
    response: list = []
    p: scapy.layers.l2.Ether
    for p in packets:
        # CDP
        if (hasattr(p, "dst") and p.dst == "01:00:0c:cc:cc:cc" and "cdp" in arg["protocols"]):
            r: dict = process_all_fields(p.load[4:], "cdp")
            r.update({"protocol": "cdp"})
        # LLDP
        elif (hasattr(p, "dst") and p.dst == "01:80:c2:00:00:0e" and "lldp" in arg["protocols"]):
            r: dict = process_all_fields(p.load, "lldp")
            r.update({"protocol": "lldp"})
        # MNDP
        elif (hasattr(p, "dport") and p.dport == 5678 and "mndp" in arg["protocols"]):
            r: dict = process_all_fields(p.load[4:], "mndp")
            r.update({"protocol": "mndp"})
        # UBNT
        # elif (p.load[:3] == b"\x01\x00\x00" and "ubnt" in arg["protocols"]):
        elif (hasattr(p, "dport") and p.dport == arg["port"] and "ubnt" in arg["protocols"]):
            r: dict = process_all_fields(p.load[4:], "ubnt")
            r.update({"protocol": "ubnt"})
        else:
            continue
        response.append(r)
    return response


def save_data(data: list, options: str, filename: str, filetype: str = "json") -> None:
    """ Save resulting data to file or convey it to stdout

    Args:
        data: list of decoded data
        filename: filename for save data (or sys.stdout)
        filetype: json, csv, txt or tree
        options: indent for json or delimiter for csv
    """
    try:
        file = open(filename, "w") if filename != "sys.stdout" else sys.stdout

        if filetype == "json":
            indent = int(options)
            json.dump(data, file, indent=indent, ensure_ascii=False)

        elif filetype == "csv":
            fieldnames = {
                "mndp": ["MAC-Address", "Identity", "Version", "Platform", "Uptime",
                        "Software-ID", "Board", "Unpack", "Interface name",
                        "IPv4-Address", "IPv6-Address", "protocol"],
                "cdp": ["Device ID", "Addresses", "Port ID", "Capabilities",
                        "Software Version", "Platform", "Unknown_type", "protocol"],
                "lldp": ["Chassis MAC address", "Port MAC address", "Time to Live",
                        "Port Description", "System Name", "System Description",
                        "Capabilities", "Management Address", "Organization Specific",
                        "protocol"],
                "ubnt": ["ipinfo", "macaddr", "hostname", "essid", "wmode", "uptime",
                         "platform", "model", "firmware", "sysid", "rest", "protocol"]
            }

            field_names: list = fieldnames[data[0]["protocol"]]

            writer = csv.DictWriter(file, fieldnames=field_names, delimiter=options)
            writer.writeheader()

            for line in data:
                writer.writerow({k:v for k,v in line.items() if k in field_names})

        elif filetype == "txt":
            for line in data:
                file.write(str(line) + "\n")

        elif filetype == "tree":
            for line in ubnt.tree_view(data):
                file.write(str(line) + "\n")

    except OSError as ex:
        print("Something wrong!!! ", repr(ex))
        exit()

    finally:
        if filename != "sys.stdout":
            file.close()


def get_nic_addresses(ifname: str) -> dict:
    """ Obtain IPv4 and MAC addresses of an interface

    Args:
        ifname: interface name

    Returns:
        Addresses dictionary
    """
    addresses = ifaddresses(ifname)
    return {"mac": addresses[AF_LINK][0]["addr"], "ip": addresses[AF_INET].copy()}


def sender(interface: str, srcaddr: str, srcport: int, nic_ip: list, delay: int,
           count: int, protocol: str) -> None:
    """ Send discovery request to LAN
        When request sends, receiver must be ready for capture responses

    Args:
        interface: Name of network interface - "eth0", "re1", etc.
        srcaddr: Source IPv4 address (one of the interface address)
        srcport: Port number
        delay: Pause between sended requests
        count: How much requests send to network
        protocol: Type of protocol
    """

    for _ in range(count):
        if protocol == "ubnt":
            if srcaddr == "":
                scapy.all.sendp(
                    scapy.layers.l2.Ether(dst="ff:ff:ff:ff:ff:ff")
                    / scapy.layers.inet.IP(dst="255.255.255.255")
                    / scapy.layers.inet.UDP(sport=srcport, dport=10001)
                    / "\x01\x00\x00\x00",
                    iface=interface,
                    verbose=False,
                    count=1,
                    )
            else:
                scapy.all.sendp(
                    scapy.layers.l2.Ether(dst="ff:ff:ff:ff:ff:ff")
                    / scapy.layers.inet.IP(src=srcaddr, dst="255.255.255.255")
                    / scapy.layers.inet.UDP(sport=srcport, dport=10001)
                    / "\x01\x00\x00\x00",
                    iface=interface,
                    verbose=False,
                    count=1,
                    )
        else:
            for addr in nic_ip:
                # addr["broadcast"] = "192.168.10.255"
                # Interface can have many ip addresses.
                # Send only one request, if srcaddr is specified
                # Or send requests from all addresses if not
                if (srcaddr is None) or (addr["addr"] == srcaddr):
                    scapy.all.sendp(
                        scapy.layers.l2.Ether(dst="ff:ff:ff:ff:ff:ff")
                        / scapy.layers.inet.IP(src=addr["addr"], dst=addr["broadcast"])
                        / scapy.layers.inet.UDP(sport=srcport, dport=5678)
                        / "\x00\x00\x00\x00",
                        iface=interface,
                        verbose=False,
                    )
        time.sleep(delay)


def receiver(interface: str, timeout: int, filtr: str) -> PacketList:
    """ Receiver for capturing responses from observed devices.
        Runs before sending discovery requests

    Args:
        interface: Name of network interface - "eth0", "re1", etc.
        timeout: How long wait responses from devices
        filtr: Packet capture conditions

    Returns:
        Captured packets
    """
    packets: PacketList = scapy.all.sniff(iface=interface, filter=filtr, timeout=timeout)
    return packets


def send_discovery_request(interface: str, srcaddr: str, srcport: int, protocols: list, timeout: int = 30,
                           silence: bool = False, delay: int = 2, count: int = 3) -> PacketList:
    """ Send discovery request and capture responses

    Args:
        interface: Name of network interface
        srcaddr: Source IPv4 address (any of inerface address)
        srcport: Port number
        protocols: List of protocols used for discovery
        timeout: How long wait responses (in seconds)
        silence: Send discovery request (True) or use passive scan (False)
        delay: Pause between requests sending
        count: How many requests to send

    Returns:
          Captured packets
    """
    packets: PacketList

    nic: dict = get_nic_addresses(interface)

    nic_ip: list = nic["ip"]

    filters: str = " or ".join(protocols)
    filters = filters.replace("cdp", "(ether dst 01:00:0c:cc:cc:cc)")
    filters = filters.replace("mndp", "(host 255.255.255.255 and udp port 5678)")
    filters = filters.replace("lldp", "(ether dst 01:80:c2:00:00:0e)")
    if srcaddr == "":
        filters = filters.replace("ubnt", "(udp dst port " + str(srcport) + ")")
    else:
        filters = filters.replace("ubnt", "(host " + srcaddr + " and udp port " + str(srcport) + ")")

    with ThreadPoolExecutor() as executor:
        # start packets capturing
        future = executor.submit(receiver, interface, timeout, filters)
        if not silence:
            # give some time for receiver initialisation
            time.sleep(2)
            # send discovering packets
            if "ubnt" in protocols:
                executor.submit(sender, interface, srcaddr, srcport, nic_ip, delay, count, "ubnt")
            if "mndp" in protocols:
                executor.submit(sender, interface, srcaddr, srcport, nic_ip, delay, count, "mndp")
        packets = future.result()
    return packets


def parse_arguments(parser: argparse.ArgumentParser) -> dict:
    """ Parse command line arguments

    Args:
        parser (argparse.ArgumentParser): ArgumentParser object

    Returns:
        dict: Parsed arguments
    """

    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "-r", "--read", type=str, help="Load data from previously stored .pcap file"
    )
    source.add_argument(
        "-i", "--interface", type=str, help="Source interface for discovery request"
    )
    parser.add_argument(
        "-a", "--address", type=str, default="",
        help="Source address for MNDP discovery request. \n If not specified, "
        + "requests will be sent to all addresses assigned to the interface. \n"
        + "(default - not specified)"
    )
    parser.add_argument(
        "-p", "--port", default=33333, type=int,
        help="Source port for UBNT discovery request (default - 33333)"
    )
    parser.add_argument(
        "-P", "--protocols", nargs="+", type=str, default=["cdp", "mndp", "lldp", "ubnt"],
        help="Protocols, used to discovery (default - cdp mndp lldp ubnt)"
    )
    parser.add_argument(
        "-m", "--mikrotik", action="store_true",
        help="Emulate MikroTik Neighbor Discovery (default - not specified)"
    )
    parser.add_argument(
        "-u", "--ubnt", action="store_true",
        help="Emulate UBNT discovery (default - not specified)"
    )
    parser.add_argument(
        "-S", "--separate-files", action="store_true",
        help="Use a separate result files for each protocol (default - don't use, "
        + " with csv type file - always used)"
    )
    parser.add_argument(
        "-s", "--silence", action="store_true",
        help="Don't send discovery packet. Use only passive capturing."
    )
    parser.add_argument(
        "-t", "--timeout", default=20, type=int,
        help="How long wait responses, in seconds (default - 20)"
    )
    parser.add_argument(
        "-c", "--count", default=3, type=int,
        help="How many discovery requests to send (default - 3)"
    )
    parser.add_argument(
        "-d", "--delay", default=2, type=int,
        help="Delay between discovery requests, seconds (default - 2)"
    )
    parser.add_argument(
        "-w", "--write", type=str, help="Save received responses to .pcap file"
    )
    parser.add_argument("-f", "--file-name", type=str,
        help="Filename for store result")
    parser.add_argument(
        "-y", "--file-type", choices=["json", "csv", "txt", "tree"], default="json",
        help='Type for storing results in file: "json", "csv", "txt", "tree" (default - "json")'
    )
    parser.add_argument(
        "--file-options", type=str, default="",
        help='For "json" files - indent (default - 4), for "csv" - delimiter (default - ",")'
    )
    parser.add_argument(
        "-o", "--output-type", choices=["json", "csv", "txt", "tree"], default="txt",
        help='Format for output results to stdout: "json", "csv", "txt", "tree" (default - "txt")'
    )
    parser.add_argument(
        "--output-options", type=str,
        help='For "json" format - indent (default - 4), for "csv" - delimiter (default - ",")'
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Disable output to stdout (default - not specified)"
    )
    arguments: dict = vars(parser.parse_args())
    if arguments["ubnt"]:
        arguments["protocols"] = ["ubnt"]
    elif arguments["mikrotik"]:
        arguments["protocols"] = ["cdp", "mndp", "lldp"]
    if arguments["file_type"]=="tree" and "ubnt" not in arguments["protocols"]:
        arguments["file_type"] = "txt"
    if arguments["file_type"]=="csv" and arguments["file_options"]=="":
        arguments["file_options"] = ","
    if arguments["file_type"]=="json" and arguments["file_options"]=="":
        arguments["file_options"] = 4
    if arguments["output_type"]=="csv" and arguments["output_options"]=="":
        arguments["output_options"] = ","
    if arguments["output_type"]=="json" and arguments["output_options"]=="":
        arguments["output_options"] = 4
    return arguments


def get_packets_from_file_or_network(arg: dict) -> PacketList:
    """ Receives packets from file or network depending on configuration

    Args:
        arg: Configuration information

    Returns:
        List of captured or roded from file packets   *******************
    """
    if exist(arg["read"]):
        try:
            packets: PacketList = scapy.all.rdpcap(arg["read"])
        except OSError as ex:
            print(f"Error while reading file {arg['read']} - ", repr(ex))
            exit()
    else:
        packets: PacketList = send_discovery_request(
            arg["interface"],
            arg["address"],
            protocols=arg["protocols"],
            srcport=arg["port"],
            timeout=arg["timeout"],
            silence=arg["silence"],
            delay=arg["delay"],
            count=arg["count"]
        )
    return packets


def get_parsed_data(packets: PacketList, arg: dict) -> list:
    """

    Args:
        packets: Captured or
        arg:

    Returns:
        List of parsed data
    """
    try:
        if exist(arg["write"]):
            scapy.all.wrpcap(arg["write"], packets)
    except OSError as ex:
        print(f"Error while writing file {arg['write']} - ", repr(ex))
        exit()
    ready_data: list = parsing(packets, arg)
    ready_data = remove_duplicates(ready_data)
    return ready_data


def save_result_to_file_or_screen(ready_data: list, arg: dict, screen: bool = False) -> None:
    if screen:
        sav_options: str = arg["output_options"]
        sav_file: str = "sys.stdout"
        sav_type: str = arg["output_type"]
    else:
        sav_options: str = arg["file_options"]
        sav_file: str = arg["file_name"]
        sav_type: str = arg["file_type"]

    if arg["separate_files"] or \
            ((sav_type == "csv" or sav_type == "tree") and len(arg["protocols"]) > 1):
        protocol_set = set()
        # find all types of protocols in captured data
        for item in ready_data:
            print(item)
            protocol_set.add(item["protocol"])
        if len(protocol_set) == 1:
            if sav_type == "tree" and ("ubnt" not in protocol_set):
                sav_type = "txt"
            save_data(ready_data, sav_options, sav_file, sav_type)
        else:
            for proto in protocol_set:
                dat: list = [x for x in ready_data if x["protocol"] == proto]
                if screen:
                    print("\n" + proto.upper() + "\n=================================")
                    save_data(dat, sav_options, sav_file, sav_type)
                else:
                    if sav_type == "tree" and proto!="ubnt":
                        save_data(dat, sav_options, proto + "_" + arg["file_name"], "txt")
                    else:
                        save_data(dat, sav_options, proto + "_" + arg["file_name"], sav_type)
    else:
        save_data(ready_data, sav_options, sav_file, sav_type)

def configure_and_run(arg: dict) -> None:
    """Run all functions by depends of received configuration parameters

    Args:
        arg (dict): Configuration parameters, getted from command line
    """

    packets: PacketList = get_packets_from_file_or_network(arg)

    if exist(packets) and len(packets) > 0:
        ready_data: list = get_parsed_data(packets, arg)

        if exist(arg["file_name"]):
            save_result_to_file_or_screen(ready_data, arg, False)

        if not arg["quiet"]:
            save_result_to_file_or_screen(ready_data, arg, True)


if __name__ == "__main__":
    configure_and_run(parse_arguments(argparse.ArgumentParser()))
